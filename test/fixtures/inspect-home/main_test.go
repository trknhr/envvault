package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectHashesHomeFileWithoutReturningContents(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".hogehoge")
	const secret = "secret-canary"
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	result, err := inspect(home, []string{".hogehoge"})
	if err != nil {
		t.Fatalf("inspect() error = %v", err)
	}
	digest := sha256.Sum256([]byte(secret))
	status := result.Files[".hogehoge"]
	if status.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("SHA256 = %q", status.SHA256)
	}
	if status.Size != int64(len(secret)) {
		t.Fatalf("Size = %d", status.Size)
	}
}
