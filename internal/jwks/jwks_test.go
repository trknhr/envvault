package jwks_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/jwks"
)

func TestExportWritesStablePublicJWKSFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backend", "credlease-jwks.json")
	body := []byte(`{"keys":[{"kid":"test-kid","kty":"OKP"}]}`)

	if err := jwks.Export(path, body); err != nil {
		t.Fatalf("Export() error = %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("file = %s, want %s", got, body)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644", info.Mode().Perm())
	}
}

func TestExportRejectsInvalidJWKS(t *testing.T) {
	err := jwks.Export(filepath.Join(t.TempDir(), "jwks.json"), []byte(`{"not_keys":[]}`))
	if err == nil {
		t.Fatal("Export() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ConfigInvalid {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ConfigInvalid)
	}
}

func TestExportRejectsPrivateJWKMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jwks.json")

	err := jwks.Export(path, []byte(`{"keys":[{"kid":"test-kid","kty":"OKP","d":"private-seed"}]}`))
	if err == nil {
		t.Fatal("Export() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ConfigInvalid {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ConfigInvalid)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("private jwks file exists or stat failed: %v", statErr)
	}
}
