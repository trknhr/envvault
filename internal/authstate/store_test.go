package authstate

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trknhr/envvault/internal/keyring"
)

func TestEncryptedDocumentRoundTripTamperAndReplacement(t *testing.T) {
	ctx := context.Background()
	store := Store{Dir: filepath.Join(t.TempDir(), "auth"), Keys: keyring.NewMemoryStore()}
	metadata := Metadata{Name: "service/work", Provider: "generic", Format: "json", TokenField: "/tokens/access"}
	doc := []byte(`{"tokens":{"access":"private-canary","refresh":"other-canary"},"padding":"` + strings.Repeat("x", 8192) + `"}`)
	created, err := store.Put(ctx, metadata, doc)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(store.Dir, created.ID+".json")
	disk, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(disk, []byte("private-canary")) || bytes.Contains(disk, []byte("other-canary")) {
		t.Fatal("authentication file contains plaintext")
	}
	if info, _ := os.Stat(filename); info.Mode().Perm() != 0600 {
		t.Fatal("authentication file permissions are not private")
	}
	if info, _ := os.Stat(store.Dir); info.Mode().Perm() != 0700 {
		t.Fatal("authentication directory permissions are not private")
	}
	record, err := store.Read(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer record.Zero()
	value, err := Token(record.Document, created.TokenField)
	if err != nil || string(value) != "private-canary" {
		t.Fatal("token extraction failed")
	}
	keyring.Zero(value)
	var tampered envelope
	json.Unmarshal(disk, &tampered)
	tampered.Metadata.TokenField = "/tokens/refresh"
	encoded, _ := json.Marshal(tampered)
	os.WriteFile(filename, encoded, 0600)
	if _, err := store.Read(ctx, created.ID); err == nil {
		t.Fatal("metadata substitution was not authenticated")
	}
	os.WriteFile(filename, disk, 0600)
	updated, err := store.Put(ctx, created, []byte(`{"tokens":{"access":"rotated-canary"}}`))
	if err != nil || updated.ID != created.ID {
		t.Fatal("replacement changed identity or failed")
	}
	after, _ := os.ReadFile(filename)
	if bytes.Equal(after, disk) {
		t.Fatal("replacement retained ciphertext")
	}
	if err := store.Delete(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(ctx, created.ID); err == nil {
		t.Fatal("deleted authentication remained readable")
	}
}

func TestAuthenticationDocumentsRejectAmbiguityAndUnsafeValues(t *testing.T) {
	for _, check := range []struct{ body, format string }{
		{`{"access_token":"first","access_token":"second"}`, "json"},
		{`{"access_token":"secret"} {}`, "json"},
		{"access_token: &token secret\nother: *token", "yaml"},
		{"access_token: first\naccess_token: second", "yaml"},
		{"1: value", "yaml"},
		{`["secret"]`, "json"},
		{strings.Repeat(" ", MaxDocumentBytes+1), "json"},
	} {
		if _, err := Parse([]byte(check.body), check.format); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("unsafe document accepted or parser leaked content")
		}
	}
	doc, err := Parse([]byte("tokens:\n  access: canary\n"), "yaml")
	if err != nil {
		t.Fatal(err)
	}
	value, err := Token(doc, "/tokens/access")
	if err != nil || string(value) != "canary" {
		t.Fatal("YAML selector did not resolve")
	}
	for _, body := range []string{`{"access_token":"Bearer envvault://another"}`, `{"access_token":"line\nbreak"}`, `{"access_token":123}`, `{"access_token":" padded "}`} {
		if _, err := Token([]byte(body), "/access_token"); err == nil {
			t.Fatal("unsafe token was accepted")
		}
	}
}

func TestAuthStoreRejectsSymlinksAndMissingKeys(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store := Store{Dir: filepath.Join(dir, "auth"), Keys: keyring.NewMemoryStore()}
	m, err := store.Put(ctx, Metadata{Name: "app", Provider: "generic", Format: "json", TokenField: "/token"}, []byte(`{"token":"secret-canary"}`))
	if err != nil {
		t.Fatal(err)
	}
	withoutKeys := store
	withoutKeys.Keys = keyring.NewMemoryStore()
	if _, err := withoutKeys.Read(ctx, m.ID); err == nil || strings.Contains(err.Error(), "secret-canary") {
		t.Fatal("missing key did not fail safely")
	}
	file := filepath.Join(store.Dir, m.ID+".json")
	os.Remove(file)
	outside := filepath.Join(dir, "outside")
	os.WriteFile(outside, []byte("secret-canary"), 0600)
	if err := os.Symlink(outside, file); err != nil {
		t.Skip(err)
	}
	if _, err := store.Read(ctx, m.ID); err == nil {
		t.Fatal("symlinked record was read")
	}
}
