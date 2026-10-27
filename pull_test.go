//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type tarEntry struct {
	name     string
	kind     byte
	link     string
	mode     int64
	data     string
	zeroMode bool
}

func syntheticArchive(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	for _, entry := range entries {
		if entry.kind == 0 {
			entry.kind = tar.TypeReg
		}
		if entry.mode == 0 && !entry.zeroMode {
			entry.mode = 0755
		}
		header := &tar.Header{Name: entry.name, Typeflag: entry.kind, Mode: entry.mode, Linkname: entry.link}
		if entry.kind == tar.TypeReg {
			header.Size = int64(len(entry.data))
		}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(archive, entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := errors.Join(archive.Close(), compressed.Close()); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func shellArchive(t *testing.T) []byte {
	t.Helper()
	return syntheticArchive(t,
		tarEntry{name: "bin/sh", kind: tar.TypeSymlink, link: "/bin/busybox"},
		tarEntry{name: "bin/busybox", data: "synthetic executable bytes"},
	)
}

func extractFixture(t *testing.T, data []byte, limits extractionLimits) (string, error) {
	t.Helper()
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	err = extractRootfs(bytes.NewReader(data), root, limits)
	return directory, errors.Join(err, root.Close())
}

func TestExtractRootfsConfinedLinksAndPermissions(t *testing.T) {
	data := syntheticArchive(t,
		tarEntry{name: "./", kind: tar.TypeDir},
		tarEntry{name: "bin/sh", kind: tar.TypeSymlink, link: "/bin/busybox"},
		tarEntry{name: "copy", kind: tar.TypeLink, link: "bin/busybox"},
		tarEntry{name: "bin/busybox", data: "synthetic executable bytes"},
		tarEntry{name: "etc/mtab", kind: tar.TypeSymlink, link: "../proc/mounts"},
		tarEntry{name: "var/run", kind: tar.TypeSymlink, link: "../run"},
		tarEntry{name: "run", kind: tar.TypeDir},
		tarEntry{name: "tmp", kind: tar.TypeDir, mode: 01777},
	)
	directory, err := extractFixture(t, data, rootfsLimits)
	if err != nil {
		t.Fatal(err)
	}
	link, err := os.Readlink(filepath.Join(directory, "bin/sh"))
	if err != nil || link != "busybox" {
		t.Fatalf("absolute rootfs link was not safely made relative: %q, %v", link, err)
	}
	original, err := os.Stat(filepath.Join(directory, "bin/busybox"))
	if err != nil {
		t.Fatal(err)
	}
	hardLinkInfo, err := os.Stat(filepath.Join(directory, "copy"))
	if err != nil || !os.SameFile(original, hardLinkInfo) {
		t.Fatalf("regular-file hard link was not preserved: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(directory, "bin/sh"))
	if err != nil || string(content) != "synthetic executable bytes" {
		t.Fatalf("confined shell link cannot be followed: %v", err)
	}
	mode, err := os.Stat(filepath.Join(directory, "tmp"))
	if err != nil || mode.Mode()&os.ModeSticky == 0 {
		t.Fatalf("safe directory sticky bit was not preserved: %v", err)
	}
}

func TestExtractRootfsRejectsUnsafeEntries(t *testing.T) {
	cases := map[string][]tarEntry{
		"parent path":       {{name: "../escaped", data: "outside"}},
		"nested parent":     {{name: "dir/../../escaped", data: "outside"}},
		"absolute path":     {{name: "/escaped", data: "outside"}},
		"ambiguous slash":   {{name: `dir\escaped`, data: "outside"}},
		"control path":      {{name: "file\nforged", data: "outside"}},
		"setuid":            {{name: "file", mode: 04755, data: "unsafe"}},
		"setgid":            {{name: "file", mode: 02755, data: "unsafe"}},
		"character device":  {{name: "device", kind: tar.TypeChar}},
		"block device":      {{name: "device", kind: tar.TypeBlock}},
		"fifo":              {{name: "pipe", kind: tar.TypeFifo}},
		"escaping symlink":  {{name: "link", kind: tar.TypeSymlink, link: "../escaped"}},
		"ambiguous symlink": {{name: "link", kind: tar.TypeSymlink, link: "other/../escaped"}},
		"escaping hardlink": {{name: "link", kind: tar.TypeLink, link: "../escaped"}},
		"absolute hardlink": {{name: "link", kind: tar.TypeLink, link: "/etc/passwd"}},
		"duplicate path": {
			{name: "file", data: "first"}, {name: "./file", data: "second"},
		},
		"symlink as parent": {
			{name: "pivot", kind: tar.TypeSymlink, link: "elsewhere"},
			{name: "pivot/file", data: "through a link"},
		},
		"hardlink to directory": {
			{name: "directory", kind: tar.TypeDir},
			{name: "link", kind: tar.TypeLink, link: "directory"},
		},
		"hardlink to symlink": {
			{name: "file", data: "safe"},
			{name: "symbolic", kind: tar.TypeSymlink, link: "file"},
			{name: "hard", kind: tar.TypeLink, link: "symbolic"},
		},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := extractFixture(t, syntheticArchive(t, entries...), rootfsLimits); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

func TestExtractRootfsCannotTraverseExistingSymlinkOutsideRoot(t *testing.T) {
	outside := t.TempDir()
	marker := filepath.Join(outside, "marker")
	if err := os.WriteFile(marker, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(directory, "pivot")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	data := syntheticArchive(t, tarEntry{name: "pivot/marker", data: "overwritten"})
	err = extractRootfs(bytes.NewReader(data), root, rootfsLimits)
	if closeErr := root.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err == nil {
		t.Fatal("existing external symlink was traversed")
	}
	content, err := os.ReadFile(marker)
	if err != nil || string(content) != "unchanged" {
		t.Fatalf("outside file was modified: %v", err)
	}
}

func TestExtractRootfsRestrictiveDirectoryModes(t *testing.T) {
	data := syntheticArchive(t,
		tarEntry{name: ".", kind: tar.TypeDir, mode: 0400},
		tarEntry{name: "outer", kind: tar.TypeDir, mode: 0400},
		tarEntry{name: "outer/inner", kind: tar.TypeDir, mode: 0400},
		tarEntry{name: "outer/inner/file", data: "retained"},
	)
	directory, err := extractFixture(t, data, rootfsLimits)
	// Restore only this test's directories before TempDir cleanup, including on failure.
	defer func() {
		for _, name := range []string{".", "outer", "outer/inner"} {
			_ = os.Chmod(filepath.Join(directory, name), 0700)
		}
	}()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".", "outer", "outer/inner"} {
		filename := filepath.Join(directory, name)
		info, err := os.Stat(filename)
		if err != nil || info.Mode().Perm() != 0400 {
			t.Fatalf("restrictive mode not preserved for %q: %v", name, err)
		}
		if err := os.Chmod(filename, 0700); err != nil {
			t.Fatal(err)
		}
	}
	content, err := os.ReadFile(filepath.Join(directory, "outer/inner/file"))
	if err != nil || string(content) != "retained" {
		t.Fatalf("directory permissions interrupted extraction: %v", err)
	}
}

func TestExtractRootfsLimitsAndCorruption(t *testing.T) {
	data := syntheticArchive(t, tarEntry{name: "one", data: "12345678"}, tarEntry{name: "two", data: "x"})
	for name, limits := range map[string]extractionLimits{
		"file size":     {bytes: 1 << 20, file: 4, entries: 10},
		"entry count":   {bytes: 1 << 20, file: 32, entries: 1},
		"expanded size": {bytes: 1000, file: 32, entries: 10},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := extractFixture(t, data, limits); err == nil {
				t.Fatal("archive limit was ignored")
			}
		})
	}
	for name, corrupted := range map[string][]byte{
		"truncated gzip":   data[:len(data)-4],
		"bad gzip trailer": append(append([]byte(nil), data[:len(data)-8]...), make([]byte, 8)...),
		"not gzip":         []byte("not an archive"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := extractFixture(t, corrupted, rootfsLimits); err == nil {
				t.Fatal("corrupt archive accepted")
			}
		})
	}
}

func TestExtractRootfsBoundsLogicalSparseFileBytes(t *testing.T) {
	const fileSize = 8 << 10
	limits := extractionLimits{bytes: 2 * fileSize, file: fileSize, entries: 10}
	for _, count := range []int{2, 3} {
		t.Run(fmt.Sprintf("%d_files", count), func(t *testing.T) {
			data := sparseArchive(t, count, fileSize)
			directory, err := extractFixture(t, data, limits)
			if count == 2 && err != nil {
				t.Fatalf("logical file bytes exactly at the limit must be accepted: %v", err)
			}
			if count == 3 && err == nil {
				t.Fatal("sparse files exceeded the cumulative logical extraction limit")
			}
			for index := range 2 {
				content, err := os.ReadFile(filepath.Join(directory, fmt.Sprintf("sparse-%d", index)))
				if err != nil || len(content) != fileSize || content[0] != 'x' || !bytes.Equal(content[1:], make([]byte, fileSize-1)) {
					t.Fatalf("valid sparse entry was not expanded correctly: %v", err)
				}
			}
			if _, err := os.Lstat(filepath.Join(directory, "sparse-2")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("the file exceeding the logical byte budget must not be created")
			}
		})
	}
}

func sparseArchive(t *testing.T, count int, logicalSize int64) []byte {
	t.Helper()
	var raw bytes.Buffer
	archive := tar.NewWriter(&raw)
	for index := range count {
		header := &tar.Header{
			Name: fmt.Sprintf("sparse-%d", index), Typeflag: tar.TypeReg, Mode: 0600, Size: 1, Format: tar.FormatPAX,
			// tar.Writer suppresses GNU sparse records. An equal-length placeholder
			// lets this fixture encode them without changing PAX record lengths.
			PAXRecords: map[string]string{
				"XYZ.sparse.major": "0", "XYZ.sparse.minor": "1", "XYZ.sparse.numblocks": "1",
				"XYZ.sparse.map": "0,1", "XYZ.sparse.size": strconv.FormatInt(logicalSize, 10),
			},
		}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write([]byte{'x'}); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if int64(raw.Len()) >= 2*logicalSize {
		t.Fatal("sparse fixture must fit within the raw stream limit")
	}
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	if _, err := compressed.Write(bytes.ReplaceAll(raw.Bytes(), []byte("XYZ.sparse."), []byte("GNU.sparse."))); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func archiveDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func trustedPullClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	client := newPullClient()
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func TestPullRootfsPublishesOnlyAfterVerification(t *testing.T) {
	data := syntheticArchive(t,
		tarEntry{name: ".", kind: tar.TypeDir, mode: 0750},
		tarEntry{name: "bin/sh", kind: tar.TypeSymlink, link: "/bin/busybox"},
		tarEntry{name: "bin/busybox", data: "synthetic executable bytes"},
	)
	destination := filepath.Join(t.TempDir(), "rootfs")
	var sawPartial atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
			sawPartial.Store(true)
		}
		_, _ = w.Write(data)
	}))
	defer server.Close()
	if err := pullRootfs(t.Context(), destination, server.URL, archiveDigest(data), trustedPullClient(t, server)); err != nil {
		t.Fatal(err)
	}
	if sawPartial.Load() {
		t.Fatal("cache became visible before download completed")
	}
	contents, err := os.ReadFile(filepath.Join(destination, "bin/sh"))
	if err != nil || string(contents) != "synthetic executable bytes" {
		t.Fatalf("complete verified rootfs was not published: %v", err)
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0750 {
		t.Fatalf("staging cleanup changed published rootfs permissions: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(destination))
	if err != nil || len(entries) != 1 || entries[0].Name() != "rootfs" {
		t.Fatalf("staging directory was not cleaned up: %v", err)
	}
}

func TestPullRootfsCleansRestrictiveDirectories(t *testing.T) {
	for _, test := range []struct {
		name    string
		entries []tarEntry
	}{
		{"root-read-only", []tarEntry{
			{name: ".", kind: tar.TypeDir, mode: 0400},
			{name: "retained", data: "small synthetic contents"},
		}},
		{"root-no-permissions", []tarEntry{
			{name: ".", kind: tar.TypeDir, zeroMode: true},
			{name: "retained", data: "small synthetic contents"},
		}},
		{"nested-read-only", []tarEntry{
			{name: "outer", kind: tar.TypeDir, mode: 0400},
			{name: "outer/inner", kind: tar.TypeDir, mode: 0400},
			{name: "outer/inner/retained", data: "small synthetic contents"},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			// Restore only known fixture directories if an assertion fails before
			// staging cleanup, so this regression also cleans up against old code.
			t.Cleanup(func() {
				entries, _ := os.ReadDir(parent)
				for _, entry := range entries {
					if !entry.IsDir() || !strings.HasPrefix(entry.Name(), ".alpine-pull-") {
						continue
					}
					root, err := os.OpenRoot(filepath.Join(parent, entry.Name()))
					if err != nil {
						t.Error(err)
						continue
					}
					for _, name := range []string{"rootfs", "rootfs/outer", "rootfs/outer/inner"} {
						_ = root.Chmod(name, 0700)
					}
					_ = root.Close()
				}
			})
			data := syntheticArchive(t, test.entries...)
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK, Header: make(http.Header),
					Body: io.NopCloser(bytes.NewReader(data)), ContentLength: int64(len(data)),
				}, nil
			})}
			if err := pullRootfs(t.Context(), filepath.Join(parent, "cache"), "https://fixture.invalid/rootfs", archiveDigest(data), client); err == nil {
				t.Fatal("fixture without bin/sh must fail validation")
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed pull left staging data: entries=%d, error=%v", len(entries), err)
			}
		})
	}
}

func TestCleanupPullStageDoesNotFollowSymlinks(t *testing.T) {
	outside := t.TempDir()
	marker := filepath.Join(outside, "marker")
	if err := os.WriteFile(marker, []byte("unchanged"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outside, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(outside, 0700) })
	stage := filepath.Join(t.TempDir(), "stage")
	rootfs := filepath.Join(stage, "rootfs")
	if err := os.MkdirAll(rootfs, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(rootfs, "outside")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rootfs, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(rootfs, 0700) })
	if err := cleanupPullStage(stage); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("private staging directory was not removed")
	}
	for name, mode := range map[string]os.FileMode{outside: 0500, marker: 0400} {
		info, err := os.Stat(name)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("cleanup changed a path outside staging: %v", err)
		}
	}
	content, err := os.ReadFile(marker)
	if err != nil || string(content) != "unchanged" {
		t.Fatalf("cleanup changed the external marker: %v", err)
	}
}

func TestPullRootfsFailuresLeaveNoCache(t *testing.T) {
	valid := shellArchive(t)
	for _, test := range []struct {
		name   string
		status int
		data   []byte
		digest string
	}{
		{name: "HTTP error", status: 500, data: valid, digest: archiveDigest(valid)},
		{name: "partial HTTP response", status: 206, data: valid, digest: archiveDigest(valid)},
		{name: "redirect", status: 302, data: valid, digest: archiveDigest(valid)},
		{name: "wrong digest", status: 200, data: valid, digest: strings.Repeat("0", 64)},
		{name: "invalid archive", status: 200, data: []byte("invalid"), digest: archiveDigest([]byte("invalid"))},
		{name: "unsafe archive", status: 200, data: syntheticArchive(t, tarEntry{name: "../escape", data: "x"})},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.digest == "" {
				test.digest = archiveDigest(test.data)
			}
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(test.status)
				_, _ = w.Write(test.data)
			}))
			defer server.Close()
			parent := t.TempDir()
			destination := filepath.Join(parent, "rootfs")
			err := pullRootfs(t.Context(), destination, server.URL, test.digest, trustedPullClient(t, server))
			if err == nil {
				t.Fatal("invalid download was published")
			}
			entries, readErr := os.ReadDir(parent)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("failure left a cache or staging data: %v", readErr)
			}
			if requests.Load() != 1 {
				t.Fatalf("unexpected follow-up request count: %d", requests.Load())
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPullRootfsDoesNotReplaceExistingCache(t *testing.T) {
	for _, kind := range []string{"file", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "existing")
			var err error
			switch kind {
			case "file":
				err = os.WriteFile(destination, []byte("existing file"), 0600)
			case "directory":
				err = os.Mkdir(destination, 0700)
			case "symlink":
				err = os.Symlink("nonexistent", destination)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(destination)
			if err != nil {
				t.Fatal(err)
			}
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Error("an existing cache must fail before download")
				return nil, errors.New("unexpected download")
			})}
			if err := pullRootfs(t.Context(), destination, alpineURL, alpineSHA256, client); err == nil {
				t.Fatal("existing cache was accepted for replacement")
			}
			after, err := os.Lstat(destination)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("existing cache was changed: %v", err)
			}
		})
	}
}

func TestDownloadArchiveBoundsSourceAndResponse(t *testing.T) {
	for _, test := range []struct {
		name     string
		encoding string
		declared string
		chunked  bool
	}{
		{name: "declared too large", declared: "999999"},
		{name: "actual too large", chunked: true},
		{name: "content encoding", encoding: "gzip"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Accept-Encoding") != "identity" {
					t.Error("archive bytes must not use negotiated content encoding")
				}
				w.Header().Set("Content-Encoding", test.encoding)
				if test.declared != "" {
					w.Header().Set("Content-Length", test.declared)
				}
				if test.chunked {
					w.(http.Flusher).Flush()
				}
				_, _ = io.WriteString(w, strings.Repeat("x", 65))
			}))
			defer server.Close()
			filename := filepath.Join(t.TempDir(), "archive")
			err := downloadArchive(t.Context(), trustedPullClient(t, server), server.URL, strings.Repeat("0", 64), filename, 64)
			if err == nil {
				t.Fatal("download boundary was ignored")
			}
		})
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("invalid source must fail before HTTP")
		return nil, errors.New("unexpected HTTP")
	})}
	for _, source := range []string{"http://127.0.0.1/archive", "https://user:password@example.test/a", "https://example.test/a#fragment"} {
		if err := downloadArchive(t.Context(), client, source, alpineSHA256, filepath.Join(t.TempDir(), "archive"), 64); err == nil {
			t.Fatal("insecure archive source accepted")
		}
	}
}

func TestDownloadArchiveTimeoutAndCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	client := trustedPullClient(t, server)
	client.Timeout = 30 * time.Millisecond
	filename := filepath.Join(t.TempDir(), "archive")
	start := time.Now()
	if err := downloadArchive(t.Context(), client, server.URL, alpineSHA256, filename, 64); err == nil {
		t.Fatal("server stalled without timing out")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("bounded HTTP timeout was not respected")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := downloadArchive(ctx, client, server.URL, alpineSHA256, filename, 64); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was not propagated: %v", err)
	}
}

func TestOfficialAlpineArchive(t *testing.T) {
	filename := os.Getenv("GOCONTAINER_TEST_ARCHIVE")
	if filename == "" {
		t.Skip("set GOCONTAINER_TEST_ARCHIVE to the pinned official archive for an offline extraction check")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if archiveDigest(data) != alpineSHA256 {
		t.Fatal("offline fixture does not match the official pinned SHA256")
	}
	directory := filepath.Join(t.TempDir(), "official")
	if err := extractArchiveFile(filename, directory); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	shell, err := root.Open("bin/sh")
	if err != nil {
		_ = root.Close()
		t.Fatal(err)
	}
	var header [20]byte
	_, readErr := io.ReadFull(shell, header[:])
	if err := errors.Join(readErr, shell.Close(), root.Close()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(header[:4], []byte{0x7f, 'E', 'L', 'F'}) || header[18] != 62 || header[19] != 0 {
		t.Fatal("bin/sh did not resolve to the expected x86_64 ELF; no executable was run")
	}
}
