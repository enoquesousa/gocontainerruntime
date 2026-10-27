//go:build linux

package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
	"unicode"
)

const (
	alpineURL = "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-minirootfs-3.24.3-x86_64.tar.gz"
	// Published at alpineURL + ".sha256"; verified against the official archive.
	alpineSHA256     = "f8e1cafba9b1b283b5d30d06f9885c8d2bc161ffe9083ade8e2e157813a53407"
	maxDownloadBytes = 16 << 20
	pullTimeout      = 60 * time.Second
)

type extractionLimits struct {
	bytes   int64
	file    int64
	entries int
}

var rootfsLimits = extractionLimits{bytes: 64 << 20, file: 32 << 20, entries: 10000}

// pull publishes a verified rootfs only when the destination does not exist.
// The operator must control the cache parent; this is not a host-user sandbox.
func pull() error {
	if runtime.GOARCH != "amd64" {
		return errors.New("the pinned Alpine rootfs requires Linux amd64")
	}
	client := newPullClient()
	defer client.CloseIdleConnections()
	fmt.Println("Downloading and verifying Alpine 3.24.3 rootfs...")
	if err := pullRootfs(context.Background(), cacheDir, alpineURL, alpineSHA256, client); err != nil {
		return err
	}
	fmt.Printf("Verified rootfs ready at %q\n", cacheDir)
	return nil
}

func newPullClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	return &http.Client{
		Transport: transport,
		Timeout:   pullTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func requireAbsent(name string) error {
	_, err := os.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect rootfs destination: %w", err)
	}
	return errors.New("rootfs cache already exists; inspect and move it before pulling again")
}

func pullRootfs(ctx context.Context, destination, imageURL, digest string, client *http.Client) (resultErr error) {
	if err := requireAbsent(destination); err != nil {
		return err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".alpine-pull-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, cleanupPullStage(stage)) }()
	archive := filepath.Join(stage, "rootfs.tar.gz")
	if err := downloadArchive(ctx, client, imageURL, digest, archive, maxDownloadBytes); err != nil {
		return err
	}
	rootfs := filepath.Join(stage, "rootfs")
	if err := extractArchiveFile(archive, rootfs); err != nil {
		return err
	}
	if err := requireAbsent(destination); err != nil {
		return err
	}
	if err := os.Rename(rootfs, destination); err != nil {
		return fmt.Errorf("publish verified rootfs: %w", err)
	}
	return nil
}

func cleanupPullStage(stage string) error {
	root, openErr := os.OpenRoot(stage)
	var walkErr, closeErr error
	if openErr == nil {
		// Restore directory access before descending. WalkDir does not follow
		// symlinks, and os.Root confines every permission change to the stage.
		walkErr = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return root.Chmod(name, 0700)
			}
			return nil
		})
		closeErr = root.Close()
	} else if errors.Is(openErr, os.ErrNotExist) {
		openErr = nil
	}
	// Still attempt removal if restoring permissions or closing the root failed.
	removeErr := os.RemoveAll(stage)
	if err := errors.Join(openErr, walkErr, closeErr, removeErr); err != nil {
		return fmt.Errorf("clean rootfs staging directory: %w", err)
	}
	return nil
}

func downloadArchive(ctx context.Context, client *http.Client, imageURL, digest, filename string, limit int64) error {
	expected, err := hex.DecodeString(digest)
	if err != nil || len(expected) != sha256.Size {
		return errors.New("invalid pinned rootfs digest")
	}
	parsed, err := url.Parse(imageURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("rootfs source must be an HTTPS URL without credentials or fragment")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imageURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download rootfs: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if err := validateArchiveResponse(response, limit); err != nil {
		return err
	}
	return saveVerifiedArchive(response.Body, filename, expected, limit)
}

func validateArchiveResponse(response *http.Response, limit int64) error {
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("rootfs download returned HTTP %d", response.StatusCode)
	}
	encoding := response.Header.Get("Content-Encoding")
	if response.Uncompressed || (encoding != "" && encoding != "identity") {
		return errors.New("unexpected HTTP content encoding for rootfs")
	}
	if response.ContentLength > limit {
		return errors.New("compressed rootfs exceeds download limit")
	}
	return nil
}

func saveVerifiedArchive(source io.Reader, filename string, expected []byte, limit int64) error {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(source, limit+1))
	closeErr := file.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return fmt.Errorf("save rootfs download: %w", err)
	}
	if n > limit {
		return errors.New("compressed rootfs exceeds download limit")
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), hex.EncodeToString(expected)) {
		return errors.New("rootfs SHA256 does not match the pinned archive")
	}
	return nil
}

func extractArchiveFile(archive, directory string) error {
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if err := os.Mkdir(directory, 0755); err != nil {
		return err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := extractRootfs(file, root, rootfsLimits); err != nil {
		return fmt.Errorf("extract rootfs: %w", err)
	}
	shell, err := root.Stat("bin/sh")
	if err != nil || !shell.Mode().IsRegular() || shell.Mode().Perm()&0111 == 0 {
		return errors.New("rootfs has no confined executable bin/sh")
	}
	return nil
}

type archiveExtractor struct {
	root      *os.Root
	limit     extractionLimits
	fileBytes int64
	seen      map[string]bool
	dirs      map[string]os.FileMode
	links     []*tar.Header
}

func extractRootfs(source io.Reader, root *os.Root, limits extractionLimits) error {
	gzipReader, err := gzip.NewReader(source)
	if err != nil {
		return err
	}
	defer func() { _ = gzipReader.Close() }()
	bounded := &io.LimitedReader{R: gzipReader, N: limits.bytes + 1}
	extractor := archiveExtractor{root: root, limit: limits, seen: make(map[string]bool), dirs: make(map[string]os.FileMode)}
	if err := extractor.read(tar.NewReader(bounded)); err != nil {
		return err
	}
	// tar EOF may precede gzip EOF; consume the trailer to validate its checksum.
	if _, err := io.Copy(io.Discard, bounded); err != nil {
		return err
	}
	if bounded.N <= 0 {
		return errors.New("expanded rootfs exceeds extraction limit")
	}
	if err := extractor.createLinks(); err != nil {
		return err
	}
	return extractor.directoryModes()
}

func (e *archiveExtractor) read(reader *tar.Reader) error {
	for count := 0; ; count++ {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if count >= e.limit.entries {
			return errors.New("rootfs has too many archive entries")
		}
		if err := e.extractEntry(reader, header); err != nil {
			return err
		}
	}
}

func archivePath(name string) (string, error) {
	if name == "" || path.IsAbs(name) || strings.Contains(name, "\\") || strings.ContainsFunc(name, unicode.IsControl) {
		return "", errors.New("invalid archive path")
	}
	for _, component := range strings.Split(name, "/") {
		if component == ".." {
			return "", errors.New("parent traversal in archive path")
		}
	}
	clean := path.Clean(name)
	if len(clean) > 4096 {
		return "", errors.New("archive path is too long")
	}
	return clean, nil
}

func archiveMode(header *tar.Header) (os.FileMode, error) {
	if header.Mode < 0 || header.Mode&^07777 != 0 || header.Mode&06000 != 0 {
		return 0, errors.New("unsupported or privileged archive permissions")
	}
	mode := os.FileMode(header.Mode & 0777)
	if header.Typeflag == tar.TypeDir && header.Mode&01000 != 0 {
		mode |= os.ModeSticky
	}
	return mode, nil
}

func (e *archiveExtractor) extractEntry(reader io.Reader, header *tar.Header) error {
	name, err := archivePath(header.Name)
	if err != nil {
		return err
	}
	mode, err := archiveMode(header)
	if err != nil {
		return err
	}
	if e.seen[name] || (name == "." && header.Typeflag != tar.TypeDir) {
		return errors.New("duplicate or invalid root archive entry")
	}
	e.seen[name] = true
	if err := e.root.MkdirAll(path.Dir(name), 0755); err != nil {
		return err
	}
	switch header.Typeflag {
	case tar.TypeDir:
		e.dirs[name] = mode
		return e.root.MkdirAll(name, 0755)
	case tar.TypeReg:
		return e.regularFile(reader, name, header.Size, mode)
	case tar.TypeSymlink, tar.TypeLink:
		copiedHeader := *header
		copiedHeader.Name = name
		e.links = append(e.links, &copiedHeader)
		return nil
	default:
		return errors.New("unsupported archive entry type")
	}
}

func (e *archiveExtractor) regularFile(reader io.Reader, name string, size int64, mode os.FileMode) error {
	if size < 0 || size > e.limit.file {
		return errors.New("archive file exceeds extraction limit")
	}
	// tar.Reader materializes sparse holes that are absent from the gzip stream.
	if size > e.limit.bytes-e.fileBytes {
		return errors.New("logical rootfs files exceed extraction limit")
	}
	e.fileBytes += size
	file, err := e.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.CopyN(file, reader, size)
	modeErr := file.Chmod(mode)
	return errors.Join(copyErr, modeErr, file.Close())
}

func confinedSymlink(name, target string) (string, error) {
	if target == "" || len(target) > 4096 || strings.Contains(target, "\\") || strings.ContainsFunc(target, unicode.IsControl) {
		return "", errors.New("invalid symbolic link target")
	}
	// Only leading '..' is accepted: a/../b is ambiguous when a is a symlink.
	downward := false
	for _, component := range strings.Split(target, "/") {
		if component == ".." && downward {
			return "", errors.New("ambiguous parent traversal in symbolic link")
		}
		if component != "" && component != "." && component != ".." {
			downward = true
		}
	}
	resolved := path.Join(path.Dir(name), target)
	if path.IsAbs(target) {
		resolved = strings.TrimPrefix(target, "/")
	}
	resolved = path.Clean(resolved)
	if resolved == ".." || strings.HasPrefix(resolved, "../") || path.IsAbs(resolved) {
		return "", errors.New("symbolic link escapes rootfs")
	}
	return filepath.Rel(path.Dir(name), resolved)
}

func (e *archiveExtractor) createLinks() error {
	// No archive write ever traverses a symlink: all parents/files already exist.
	for _, header := range e.links {
		if header.Typeflag == tar.TypeLink {
			if err := e.hardLink(header); err != nil {
				return err
			}
			continue
		}
		target, err := confinedSymlink(header.Name, header.Linkname)
		if err != nil {
			return err
		}
		if err := e.root.Symlink(target, header.Name); err != nil {
			return err
		}
	}
	return nil
}

func (e *archiveExtractor) hardLink(header *tar.Header) error {
	target, err := archivePath(header.Linkname)
	if err != nil {
		return err
	}
	info, err := e.root.Lstat(target)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("hard link target must be an existing regular rootfs file")
	}
	return e.root.Link(target, header.Name)
}

func (e *archiveExtractor) directoryModes() error {
	names := make([]string, 0, len(e.dirs))
	for name := range e.dirs {
		names = append(names, name)
	}
	slices.SortFunc(names, deeperDirectoryFirst)
	for _, name := range names {
		dir, err := e.root.Open(name)
		if err != nil {
			return err
		}
		if err := errors.Join(dir.Chmod(e.dirs[name]), dir.Close()); err != nil {
			return err
		}
	}
	return nil
}

func deeperDirectoryFirst(a, b string) int {
	if a == b {
		return 0
	}
	if a == "." {
		return 1
	}
	if b == "." {
		return -1
	}
	if depth := strings.Count(b, "/") - strings.Count(a, "/"); depth != 0 {
		return depth
	}
	return strings.Compare(a, b)
}
