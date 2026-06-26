package talos_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/trknhr/envvault/internal/clerr"
	runtimetalos "github.com/trknhr/envvault/internal/runtime/talos"
)

func TestInstallDownloadsAndVerifiesPinnedArtifact(t *testing.T) {
	body := []byte("talos-binary")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/talos" {
			t.Fatalf("path = %q, want /talos", r.URL.Path)
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	installer := runtimetalos.NewInstaller(server.Client(), cacheDir)
	artifact, err := installer.Install(context.Background(), runtimetalos.Manifest{
		Version: "v0.1.0",
		Artifacts: []runtimetalos.Artifact{
			{
				OS:     "darwin",
				Arch:   "arm64",
				URL:    server.URL + "/wrong",
				SHA256: digest([]byte("wrong")),
			},
			{
				OS:     "linux",
				Arch:   "amd64",
				URL:    server.URL + "/talos",
				SHA256: digest(body),
			},
		},
	}, runtimetalos.Platform{OS: "linux", Arch: "amd64"})
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}

	if artifact.Version != "v0.1.0" {
		t.Fatalf("Version = %q", artifact.Version)
	}
	got, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("artifact body = %q, want %q", got, body)
	}
	info, err := os.Stat(artifact.Path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %v, want 0755", info.Mode().Perm())
	}
	if filepath.Dir(artifact.Path) != cacheDir {
		t.Fatalf("artifact dir = %q, want %q", filepath.Dir(artifact.Path), cacheDir)
	}
}

func TestInstallExtractsTalosBinaryFromTarGzArtifact(t *testing.T) {
	body := []byte("talos-binary-from-tar")
	archive := tarGzWithFile(t, "talos", body)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/talos.tar.gz" {
			t.Fatalf("path = %q, want /talos.tar.gz", r.URL.Path)
		}
		_, _ = w.Write(archive)
	}))
	defer server.Close()

	installer := runtimetalos.NewInstaller(server.Client(), t.TempDir())
	artifact, err := installer.Install(context.Background(), runtimetalos.Manifest{
		Version: "v0.1.0",
		Artifacts: []runtimetalos.Artifact{{
			OS:     "linux",
			Arch:   "amd64",
			URL:    server.URL + "/talos.tar.gz",
			SHA256: digest(archive),
		}},
	}, runtimetalos.Platform{OS: "linux", Arch: "amd64"})
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}

	got, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("extracted artifact body = %q, want %q", got, body)
	}
}

func TestInstallExtractsTalosBinaryFromZipArtifact(t *testing.T) {
	body := []byte("talos-binary-from-zip")
	archive := zipWithFile(t, "talos.exe", body)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/talos.zip" {
			t.Fatalf("path = %q, want /talos.zip", r.URL.Path)
		}
		_, _ = w.Write(archive)
	}))
	defer server.Close()

	installer := runtimetalos.NewInstaller(server.Client(), t.TempDir())
	artifact, err := installer.Install(context.Background(), runtimetalos.Manifest{
		Version: "v0.1.0",
		Artifacts: []runtimetalos.Artifact{{
			OS:     "windows",
			Arch:   "amd64",
			URL:    server.URL + "/talos.zip",
			SHA256: digest(archive),
		}},
	}, runtimetalos.Platform{OS: "windows", Arch: "amd64"})
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if filepath.Base(artifact.Path) != "talos-v0.1.0-windows-amd64.exe" {
		t.Fatalf("artifact path = %q, want windows executable name", artifact.Path)
	}

	got, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("extracted artifact body = %q, want %q", got, body)
	}
}

func TestInstallRejectsChecksumMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tampered"))
	}))
	defer server.Close()

	installer := runtimetalos.NewInstaller(server.Client(), t.TempDir())
	_, err := installer.Install(context.Background(), runtimetalos.Manifest{
		Version: "v0.1.0",
		Artifacts: []runtimetalos.Artifact{{
			OS:     "linux",
			Arch:   "amd64",
			URL:    server.URL,
			SHA256: digest([]byte("expected")),
		}},
	}, runtimetalos.Platform{OS: "linux", Arch: "amd64"})
	if err == nil {
		t.Fatal("Install() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.RuntimeIncompatible {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.RuntimeIncompatible)
	}
}

func TestInstallReusesCachedArtifactOnlyWhenDigestMatches(t *testing.T) {
	cacheDir := t.TempDir()
	body := []byte("cached-talos")
	artifactPath := filepath.Join(cacheDir, "talos-v0.1.0-linux-amd64")
	if err := os.WriteFile(artifactPath, body, 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer server.Close()

	installer := runtimetalos.NewInstaller(server.Client(), cacheDir)
	artifact, err := installer.Install(context.Background(), runtimetalos.Manifest{
		Version: "v0.1.0",
		Artifacts: []runtimetalos.Artifact{{
			OS:     "linux",
			Arch:   "amd64",
			URL:    server.URL,
			SHA256: digest(body),
		}},
	}, runtimetalos.Platform{OS: "linux", Arch: "amd64"})
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if artifact.Path != artifactPath {
		t.Fatalf("Path = %q, want %q", artifact.Path, artifactPath)
	}
	if requests != 0 {
		t.Fatalf("requests = %d, want 0", requests)
	}
}

func TestManifestCachedArtifactPathsForRawBinary(t *testing.T) {
	cacheDir := t.TempDir()

	paths, err := (runtimetalos.Manifest{
		Version: "v0.1.0",
		Artifacts: []runtimetalos.Artifact{{
			OS:     "linux",
			Arch:   "amd64",
			URL:    "https://example.com/talos",
			SHA256: digest([]byte("body")),
		}},
	}).CachedArtifactPaths(cacheDir, runtimetalos.Platform{OS: "linux", Arch: "amd64"})
	if err != nil {
		t.Fatalf("CachedArtifactPaths() error = %v", err)
	}

	if paths.Binary != filepath.Join(cacheDir, "talos-v0.1.0-linux-amd64") {
		t.Fatalf("Binary = %q", paths.Binary)
	}
	if paths.Archive != "" {
		t.Fatalf("Archive = %q, want empty", paths.Archive)
	}
}

func TestManifestCachedArtifactPathsForArchive(t *testing.T) {
	cacheDir := t.TempDir()

	paths, err := (runtimetalos.Manifest{
		Version: "v0.1.0",
		Artifacts: []runtimetalos.Artifact{{
			OS:     "darwin",
			Arch:   "arm64",
			URL:    "https://example.com/talos.tar.gz",
			SHA256: digest([]byte("archive")),
		}},
	}).CachedArtifactPaths(cacheDir, runtimetalos.Platform{OS: "darwin", Arch: "arm64"})
	if err != nil {
		t.Fatalf("CachedArtifactPaths() error = %v", err)
	}

	if paths.Binary != filepath.Join(cacheDir, "talos-v0.1.0-darwin-arm64") {
		t.Fatalf("Binary = %q", paths.Binary)
	}
	if paths.Archive != filepath.Join(cacheDir, "talos-v0.1.0-darwin-arm64.tar.gz") {
		t.Fatalf("Archive = %q", paths.Archive)
	}
}

func TestInstallRejectsMissingPlatform(t *testing.T) {
	installer := runtimetalos.NewInstaller(http.DefaultClient, t.TempDir())
	_, err := installer.Install(context.Background(), runtimetalos.Manifest{
		Version: "v0.1.0",
		Artifacts: []runtimetalos.Artifact{{
			OS:     "darwin",
			Arch:   "arm64",
			URL:    "https://example.com/talos",
			SHA256: digest([]byte("body")),
		}},
	}, runtimetalos.Platform{OS: "linux", Arch: "amd64"})
	if err == nil {
		t.Fatal("Install() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.RuntimeIncompatible {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.RuntimeIncompatible)
	}
}

func digest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func tarGzWithFile(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0o755,
		Size: int64(len(body)),
	}); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatalf("tar Write() error = %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close() error = %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip Close() error = %v", err)
	}
	return buffer.Bytes()
}

func zipWithFile(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	zw := zip.NewWriter(&buffer)
	writer, err := zw.Create(name)
	if err != nil {
		t.Fatalf("zip Create() error = %v", err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatalf("zip Write() error = %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip Close() error = %v", err)
	}
	return buffer.Bytes()
}
