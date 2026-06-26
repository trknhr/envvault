package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPackageWritesArchiveAndChecksums(t *testing.T) {
	repoRoot := findRepoRoot(t)
	distDir := t.TempDir()
	binaryPath := filepath.Join(t.TempDir(), "envvault")
	if err := os.WriteFile(binaryPath, []byte("fake binary"), 0o755); err != nil {
		t.Fatalf("WriteFile(binary) error = %v", err)
	}
	var stdout, stderr bytes.Buffer

	code := run([]string{
		"package",
		"--repo-root", repoRoot,
		"--version", "v0.1.0",
		"--platform", "linux/amd64",
		"--binary", binaryPath,
		"--dist", distDir,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "envvault_v0.1.0_linux_amd64.tar.gz") {
		t.Fatalf("stdout = %q, want archive name", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(distDir, "envvault_v0.1.0_linux_amd64.tar.gz")); err != nil {
		t.Fatalf("release archive missing: %v", err)
	}
	checksums, err := os.ReadFile(filepath.Join(distDir, "SHA256SUMS"))
	if err != nil {
		t.Fatalf("ReadFile(SHA256SUMS) error = %v", err)
	}
	if !strings.Contains(string(checksums), "envvault_v0.1.0_linux_amd64.tar.gz") {
		t.Fatalf("SHA256SUMS = %q, want archive entry", string(checksums))
	}
	if strings.Contains(stdout.String()+stderr.String(), "secret-canary") {
		t.Fatalf("output leaked secret marker; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunPackagePreservesExistingChecksumEntries(t *testing.T) {
	repoRoot := findRepoRoot(t)
	distDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(distDir, "SHA256SUMS"), []byte("abc123  existing.tar.gz\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(existing SHA256SUMS) error = %v", err)
	}
	binaryPath := filepath.Join(t.TempDir(), "envvault")
	if err := os.WriteFile(binaryPath, []byte("fake binary"), 0o755); err != nil {
		t.Fatalf("WriteFile(binary) error = %v", err)
	}
	var stdout, stderr bytes.Buffer

	code := run([]string{
		"package",
		"--repo-root", repoRoot,
		"--version", "v0.1.0",
		"--platform", "linux/amd64",
		"--binary", binaryPath,
		"--dist", distDir,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	checksums, err := os.ReadFile(filepath.Join(distDir, "SHA256SUMS"))
	if err != nil {
		t.Fatalf("ReadFile(SHA256SUMS) error = %v", err)
	}
	for _, want := range []string{"abc123  existing.tar.gz", "envvault_v0.1.0_linux_amd64.tar.gz"} {
		if !strings.Contains(string(checksums), want) {
			t.Fatalf("SHA256SUMS = %q, want %q", string(checksums), want)
		}
	}
}

func TestRunPackageRejectsMissingRequiredArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"package", "--version", "v0.1.0"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage: envvault-release package") {
		t.Fatalf("stderr = %q, want usage", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRunPackageManifestsWritesHomebrewAndScoopFiles(t *testing.T) {
	distDir := t.TempDir()
	checksums := strings.Join([]string{
		strings.Repeat("a", 64) + "  envvault_v0.1.0_darwin_amd64.tar.gz",
		strings.Repeat("b", 64) + "  envvault_v0.1.0_darwin_arm64.tar.gz",
		strings.Repeat("c", 64) + "  envvault_v0.1.0_linux_amd64.tar.gz",
		strings.Repeat("d", 64) + "  envvault_v0.1.0_linux_arm64.tar.gz",
		strings.Repeat("e", 64) + "  envvault_v0.1.0_windows_amd64.zip",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(distDir, "SHA256SUMS"), []byte(checksums), 0o644); err != nil {
		t.Fatalf("WriteFile(SHA256SUMS) error = %v", err)
	}
	var stdout, stderr bytes.Buffer

	code := run([]string{
		"package-manifests",
		"--version", "v0.1.0",
		"--base-url", "https://github.com/trknhr/envvault/releases/download/v0.1.0",
		"--dist", distDir,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	for _, rel := range []string{"homebrew/envvault.rb", "scoop/envvault.json"} {
		if !strings.Contains(stdout.String(), rel) {
			t.Fatalf("stdout = %q, want %s", stdout.String(), rel)
		}
		if _, err := os.Stat(filepath.Join(distDir, rel)); err != nil {
			t.Fatalf("%s missing: %v", rel, err)
		}
	}
	homebrew, err := os.ReadFile(filepath.Join(distDir, "homebrew", "envvault.rb"))
	if err != nil {
		t.Fatalf("ReadFile(homebrew formula) error = %v", err)
	}
	for _, want := range []string{
		"class Envvault < Formula",
		`url "https://github.com/trknhr/envvault/releases/download/v0.1.0/envvault_v0.1.0_darwin_arm64.tar.gz"`,
		strings.Repeat("d", 64),
		`system "#{bin}/envvault", "completion", "bash"`,
	} {
		if !strings.Contains(string(homebrew), want) {
			t.Fatalf("homebrew formula missing %q:\n%s", want, string(homebrew))
		}
	}
	scoop, err := os.ReadFile(filepath.Join(distDir, "scoop", "envvault.json"))
	if err != nil {
		t.Fatalf("ReadFile(scoop manifest) error = %v", err)
	}
	for _, want := range []string{
		`"version": "0.1.0"`,
		`"url": "https://github.com/trknhr/envvault/releases/download/v0.1.0/envvault_v0.1.0_windows_amd64.zip"`,
		`"hash": "` + strings.Repeat("e", 64) + `"`,
		`"bin": "envvault.exe"`,
	} {
		if !strings.Contains(string(scoop), want) {
			t.Fatalf("scoop manifest missing %q:\n%s", want, string(scoop))
		}
	}
	if strings.Contains(stdout.String()+stderr.String()+string(homebrew)+string(scoop), "secret-canary") {
		t.Fatalf("package manifest generation leaked secret marker")
	}
}

func TestRunPackageManifestsRejectsMissingRequiredArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"package-manifests", "--version", "v0.1.0"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage: envvault-release package-manifests") {
		t.Fatalf("stderr = %q, want usage", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repo root not found")
		}
		dir = parent
	}
}
