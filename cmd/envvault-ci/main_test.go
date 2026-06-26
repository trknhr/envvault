package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretScanReportsNonSourceCanaryWithoutLeakingValue(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cache.bin"), []byte{0, 1, 2, 's', 'e', 'c', 'r', 'e', 't', '-', 'c', 'a', 'n', 'a', 'r', 'y'}, 0o600); err != nil {
		t.Fatalf("WriteFile(cache.bin) error = %v", err)
	}
	var stdout, stderr bytes.Buffer

	code := run([]string{"secret-scan", root}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("run() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "secret marker found") {
		t.Fatalf("stderr = %q, want secret marker found", stderr.String())
	}
	if strings.Contains(stderr.String(), "secret-canary") || stdout.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want no marker disclosure and empty stdout", stdout.String(), stderr.String())
	}
}

func TestSecretScanIgnoresSourceDocsAndGoSum(t *testing.T) {
	root := t.TempDir()
	for _, item := range []struct {
		path string
		body string
	}{
		{path: "source.go", body: `package p
const canary = "secret-canary"
`},
		{path: "README.md", body: "secret-canary documentation\n"},
		{path: "go.sum", body: "example.com/mod secret-canary\n"},
	} {
		if err := os.WriteFile(filepath.Join(root, item.path), []byte(item.body), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", item.path, err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "audit.jsonl"), []byte(`{"event":"ok"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(audit) error = %v", err)
	}
	var stdout, stderr bytes.Buffer

	code := run([]string{"secret-scan", root}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want both empty", stdout.String(), stderr.String())
	}
}

func TestSecretScanRejectsUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"unknown"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage: envvault-ci secret-scan") {
		t.Fatalf("stderr = %q, want usage", stderr.String())
	}
}
