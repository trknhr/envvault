package transfer

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/trknhr/envvault/internal/authstate"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/keyring"
)

func TestAuthImportSaveFailureRestoresOldDocumentAndRemovesNewKey(t *testing.T) {
	ctx := context.Background()
	keys := keyring.NewMemoryStore()
	store := authstate.Store{Dir: filepath.Join(t.TempDir(), "auth"), Keys: keys}
	metadata := authstate.Metadata{Name: "app/existing", Provider: "generic", Format: "json", TokenField: "/token"}
	stored, err := store.Put(ctx, metadata, []byte(`{"token":"original-canary"}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.DefaultFile()
	cfg.Version, cfg.AuthProfiles = 2, map[string]string{metadata.Name: stored.ID}
	newMetadata := metadata
	newMetadata.Name = "app/new"
	bundle := Bundle{AuthProfiles: []AuthProfile{{Metadata: metadata, Document: []byte(`{"token":"replacement-canary"}`)}, {Metadata: newMetadata, Document: []byte(`{"token":"new-canary"}`)}}}
	if _, err := ApplyWithAuth(ctx, keys, cfg, bundle, store, true, func(config.File) error { return errors.New("save failed") }); err == nil {
		t.Fatal("failed configuration commit reported success")
	}
	record, err := store.Read(ctx, stored.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer record.Zero()
	value, err := authstate.Token(record.Document, "/token")
	defer keyring.Zero(value)
	if err != nil || string(value) != "original-canary" {
		t.Fatal("failed import changed existing authentication")
	}
	entries, _ := os.ReadDir(store.Dir)
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" && entry.Name() != stored.ID+".json" {
			t.Fatal("failed import retained a new live record")
		}
	}
}

func TestAuthExportImportsWithFreshLocalEncryptionKeys(t *testing.T) {
	ctx := context.Background()
	keys := keyring.NewMemoryStore()
	store := authstate.Store{Dir: filepath.Join(t.TempDir(), "auth"), Keys: keys}
	meta, err := store.Put(ctx, authstate.Metadata{Name: "app/work", Provider: "generic", Format: "json", TokenField: "/token"}, []byte(`{"token":"export-canary"}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.DefaultFile()
	cfg.Version = 2
	cfg.AuthProfiles = map[string]string{meta.Name: meta.ID}
	bundle, err := CollectWithAuth(ctx, keys, cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Zero()
	sealed, err := Seal(bundle, []byte("test-passphrase"), TestKDFParams())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("export-canary")) {
		t.Fatal("encrypted export contains plaintext")
	}
	opened, err := Open([]byte("test-passphrase"), sealed)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Zero()
	newKeys := keyring.NewMemoryStore()
	destination := authstate.Store{Dir: filepath.Join(t.TempDir(), "auth"), Keys: newKeys}
	newConfig, _ := config.DefaultFile()
	result, err := ApplyWithAuth(ctx, newKeys, newConfig, opened, destination, false, func(cfg config.File) error { newConfig = cfg; return nil })
	if err != nil || len(result.ImportedAuthProfiles) != 1 {
		t.Fatalf("authentication transfer failed: %v", err)
	}
	newID := newConfig.AuthProfiles[meta.Name]
	if newID == meta.ID {
		t.Fatal("import reused source key identity")
	}
	record, err := destination.Read(ctx, newID)
	if err != nil {
		t.Fatal(err)
	}
	defer record.Zero()
	token, err := authstate.Token(record.Document, record.Metadata.TokenField)
	if err != nil || string(token) != "export-canary" {
		t.Fatal("import lost authentication document")
	}
	if _, err := Collect(ctx, keys, cfg); err == nil {
		t.Fatal("legacy collection silently omitted auth state")
	}
}
