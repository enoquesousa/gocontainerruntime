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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type tarEntry struct {
	name string
	kind byte
	link string
	mode int64
	data string
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
		if entry.mode == 0 {
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
	data := shellArchive(t)
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
	entries, err := os.ReadDir(filepath.Dir(destination))
	if err != nil || len(entries) != 1 || entries[0].Name() != "rootfs" {
		t.Fatalf("staging directory was not cleaned up: %v", err)
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
