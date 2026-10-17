package transfer_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/transfer"
)

func TestEncryptDecryptRoundTripHidesPlaintext(t *testing.T) {
	secret := []byte("envvault-secret-canary-9f3a\n\x00\xff")
	passphrase := []byte("correct horse battery")
	file, err := transfer.Encrypt(passphrase, secret, transfer.TestKDFParams())
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if bytes.Contains(file, secret) || bytes.Contains(file, passphrase) {
		t.Fatal("export file contained plaintext secret or passphrase")
	}
	if !bytes.Contains(file, []byte(`"envvault_export":1`)) || !bytes.Contains(file, []byte(`"name":"argon2id"`)) || !bytes.Contains(file, []byte(`"aead":"aes-256-gcm"`)) {
		t.Fatalf("file = %s, want versioned argon2id envelope", file)
	}
	got, err := transfer.Decrypt(passphrase, file)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("Decrypt() = %q, want original plaintext", got)
	}
	keyring.Zero(got)
	keyring.Zero(secret)
}

func TestDecryptRejectsWrongPassphraseAndTampering(t *testing.T) {
	secret := []byte("envvault-secret-canary-9f3a")
	file, err := transfer.Encrypt([]byte("correct horse battery"), secret, transfer.TestKDFParams())
	if err != nil {
		t.Fatal(err)
	}

	_, err = transfer.Decrypt([]byte("wrong horse battery"), file)
	if err == nil || !strings.Contains(err.Error(), "wrong passphrase") || strings.Contains(err.Error(), "tampered") {
		t.Fatalf("wrong passphrase error = %v", err)
	}
	if bytes.Contains([]byte(err.Error()), secret) {
		t.Fatalf("error leaked secret: %v", err)
	}

	tampered := tamperCiphertext(t, file)
	_, err = transfer.Decrypt([]byte("correct horse battery"), tampered)
	if err == nil || !strings.Contains(err.Error(), "export file was tampered with") || strings.Contains(err.Error(), "wrong passphrase") {
		t.Fatalf("tamper error = %v", err)
	}
	if bytes.Contains([]byte(err.Error()), secret) {
		t.Fatalf("tamper error leaked secret: %v", err)
	}

	header := tamperNonce(t, file)
	_, err = transfer.Decrypt([]byte("correct horse battery"), header)
	if err == nil || !strings.Contains(err.Error(), "wrong passphrase or export header was modified") {
		t.Fatalf("header tamper error = %v", err)
	}
}

func TestDecryptRejectsUnsupportedVersionAndWeakKDF(t *testing.T) {
	file, err := transfer.Encrypt([]byte("correct horse battery"), []byte("plaintext-value"), transfer.TestKDFParams())
	if err != nil {
		t.Fatal(err)
	}
	versioned := replaceJSONField(t, file, "envvault_export", float64(2))
	_, err = transfer.Decrypt([]byte("correct horse battery"), versioned)
	if err == nil || !strings.Contains(err.Error(), "unsupported export version") {
		t.Fatalf("version error = %v", err)
	}

	weak := map[string]any{}
	if err := json.Unmarshal(file, &weak); err != nil {
		t.Fatal(err)
	}
	kdf := weak["kdf"].(map[string]any)
	kdf["memory"] = float64(1024)
	weak["kdf"] = kdf
	body, err := json.Marshal(weak)
	if err != nil {
		t.Fatal(err)
	}
	_, err = transfer.Decrypt([]byte("correct horse battery"), body)
	if err == nil || !strings.Contains(err.Error(), "export file is invalid") {
		t.Fatalf("weak kdf error = %v", err)
	}

	_, err = transfer.Decrypt(nil, file)
	if err == nil || !strings.Contains(err.Error(), "wrong passphrase") {
		t.Fatalf("empty passphrase error = %v", err)
	}
	_, err = transfer.Encrypt([]byte("short"), []byte("plaintext-value"), transfer.TestKDFParams())
	if err == nil || !strings.Contains(err.Error(), "at least 8 characters") {
		t.Fatalf("short passphrase error = %v", err)
	}
}

func TestCollectSealOpenApplyRoundTripAndConflicts(t *testing.T) {
	ctx := context.Background()
	source := keyring.NewMemoryStore()
	cfg := baseConfig("source-install")
	cfg.AddCredential("api/dev")
	cfg.Profiles["app/dev"] = config.Profile{
		Kind:           profile.KindInject,
		CredentialName: "database/dev",
		ProjectBinding: config.ProjectBinding{Mode: profile.ProjectBindingNone},
	}
	cfg.Profiles["api/dev"] = config.Profile{
		Kind:           profile.KindProviderProxy,
		CredentialName: "api/dev",
		AuthMode:       "bearer",
		Provider:       "generic",
		TargetURL:      "https://api.example.com/v1",
		AllowedPaths:   []string{"/chat/completions"},
		AllowedMethods: []string{"POST"},
		LocalTokenTTL:  config.Duration(time.Minute),
		ProjectBinding: config.ProjectBinding{Mode: profile.ProjectBindingNone},
	}
	secret := []byte("database-canary-\x00\xff")
	apiSecret := []byte("api-canary")
	if err := source.Put(ctx, keyring.CredentialValue("database/dev"), secret); err != nil {
		t.Fatal(err)
	}
	if err := source.Put(ctx, keyring.CredentialValue("api/dev"), apiSecret); err != nil {
		t.Fatal(err)
	}
	if err := source.Put(ctx, keyring.ProfileParentKey("app/dev"), []byte("parent-key-canary")); err != nil {
		t.Fatal(err)
	}
	if err := source.Put(ctx, keyring.TalosHMACKey(), []byte("talos-hmac-canary")); err != nil {
		t.Fatal(err)
	}

	bundle, err := transfer.Collect(ctx, source, cfg)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	defer bundle.Zero()
	file, err := transfer.Seal(bundle, []byte("correct horse battery"), transfer.TestKDFParams())
	if err != nil {
		t.Fatal(err)
	}
	for _, hidden := range [][]byte{secret, apiSecret, []byte("parent-key-canary"), []byte("talos-hmac-canary"), []byte("correct horse battery"), []byte("source-install")} {
		if bytes.Contains(file, hidden) {
			t.Fatalf("export file leaked %q", hidden)
		}
	}
	opened, err := transfer.Open([]byte("correct horse battery"), file)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Zero()
	if len(opened.Credentials) != 2 || opened.Credentials[0].Name != "api/dev" || opened.Credentials[1].Name != "database/dev" {
		t.Fatalf("credentials = %#v", namesOnly(opened))
	}
	if !bytes.Equal(opened.Credentials[1].Value, secret) {
		t.Fatalf("database credential = %q", opened.Credentials[1].Value)
	}
	if _, ok := opened.Profiles["app/dev"]; !ok || opened.Profiles["api/dev"].TargetURL != "https://api.example.com/v1" {
		t.Fatalf("profiles = %#v", opened.Profiles)
	}

	dest := keyring.NewMemoryStore()
	destCfg := baseConfig("dest-install")
	path := filepath.Join(t.TempDir(), "config.yaml")
	result, err := transfer.Apply(ctx, dest, destCfg, opened, false, func(cfg config.File) error {
		return config.Save(path, cfg)
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if strings.Join(result.ImportedCredentials, ",") != "api/dev,database/dev" || strings.Join(result.ImportedProfiles, ",") != "api/dev,app/dev" {
		t.Fatalf("result = %#v", result)
	}
	got, err := dest.Get(ctx, keyring.CredentialValue("database/dev"))
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("imported database = %q, error = %v", got, err)
	}
	if _, err := dest.Get(ctx, keyring.TalosHMACKey()); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("talos key error = %v, want not found", err)
	}
	if _, err := dest.Get(ctx, keyring.ProfileParentKey("app/dev")); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("parent key error = %v, want not found", err)
	}
	saved, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Installation.ID != "dest-install" {
		t.Fatalf("installation = %q", saved.Installation.ID)
	}
	if saved.Profiles["app/dev"].Kind != profile.KindInject || saved.Profiles["api/dev"].AllowedMethods[0] != "POST" {
		t.Fatalf("saved profiles = %#v", saved.Profiles)
	}

	opened.Credentials[1].Value = []byte("replacement-canary")
	opened.Profiles["app/dev"] = config.Profile{
		Kind:           profile.KindInject,
		CredentialName: "database/dev",
		ProjectBinding: config.ProjectBinding{Mode: profile.ProjectBindingPathHash, PathHash: "sha256:dest"},
	}
	again, err := transfer.Apply(ctx, dest, saved, opened, false, func(cfg config.File) error {
		return config.Save(path, cfg)
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(again.SkippedCredentials, ",") != "api/dev,database/dev" || strings.Join(again.SkippedProfiles, ",") != "api/dev,app/dev" {
		t.Fatalf("skip result = %#v", again)
	}
	got, err = dest.Get(ctx, keyring.CredentialValue("database/dev"))
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("skipped database = %q, error = %v", got, err)
	}
	saved, err = config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Profiles["app/dev"].ProjectBinding.PathHash != "" {
		t.Fatalf("skip replaced profile binding: %#v", saved.Profiles["app/dev"].ProjectBinding)
	}

	replaced, err := transfer.Apply(ctx, dest, saved, opened, true, func(cfg config.File) error {
		return config.Save(path, cfg)
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(replaced.ReplacedCredentials, ",") != "api/dev,database/dev" || strings.Join(replaced.ReplacedProfiles, ",") != "api/dev,app/dev" {
		t.Fatalf("replace result = %#v", replaced)
	}
	got, err = dest.Get(ctx, keyring.CredentialValue("database/dev"))
	if err != nil || !bytes.Equal(got, []byte("replacement-canary")) {
		t.Fatalf("replaced database = %q, error = %v", got, err)
	}
	saved, err = config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Profiles["app/dev"].ProjectBinding.PathHash != "sha256:dest" {
		t.Fatalf("binding = %#v", saved.Profiles["app/dev"].ProjectBinding)
	}
}

func TestApplyRollsBackWhenSaveFails(t *testing.T) {
	ctx := context.Background()
	store := keyring.NewMemoryStore()
	if err := store.Put(ctx, keyring.CredentialValue("database/dev"), []byte("previous-canary")); err != nil {
		t.Fatal(err)
	}
	bundle := transfer.Bundle{
		Credentials: []transfer.Credential{
			{Name: "database/dev", Value: []byte("replacement-canary")},
			{Name: "api/dev", Value: []byte("api-canary")},
		},
		Profiles: map[string]config.Profile{
			"bad": {Kind: "nope"},
		},
	}
	_, applyErr := transfer.Apply(ctx, store, baseConfig("dest-install"), bundle, true, func(cfg config.File) error {
		return config.Save(filepath.Join(t.TempDir(), "config.yaml"), cfg)
	})
	if applyErr == nil {
		t.Fatal("Apply() error = nil, want invalid profile")
	}
	got, err := store.Get(ctx, keyring.CredentialValue("database/dev"))
	if err != nil || !bytes.Equal(got, []byte("previous-canary")) {
		t.Fatalf("database after rollback = %q, error = %v", got, err)
	}
	if _, err := store.Get(ctx, keyring.CredentialValue("api/dev")); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("created credential error = %v, want not found", err)
	}
	if bytes.Contains([]byte(applyErr.Error()), []byte("replacement-canary")) || bytes.Contains([]byte(applyErr.Error()), []byte("api-canary")) {
		t.Fatalf("error leaked secret: %v", applyErr)
	}
}

func TestCollectRejectsMissingAndEmptyExports(t *testing.T) {
	ctx := context.Background()
	cfg := baseConfig("source-install")
	cfg.AddCredential("database/dev")
	_, err := transfer.Collect(ctx, keyring.NewMemoryStore(), cfg)
	if err == nil || !strings.Contains(err.Error(), "database/dev is not in the OS credential store") {
		t.Fatalf("missing error = %v", err)
	}
	store := keyring.NewMemoryStore()
	if err := store.Put(ctx, keyring.CredentialValue("database/dev"), []byte{}); err != nil {
		t.Fatal(err)
	}
	_, err = transfer.Collect(ctx, store, cfg)
	if err == nil || !strings.Contains(err.Error(), "database/dev is empty") {
		t.Fatalf("empty error = %v", err)
	}
	_, err = transfer.Collect(ctx, store, baseConfig("source-install"))
	if err == nil || !strings.Contains(err.Error(), "nothing to export") {
		t.Fatalf("empty bundle error = %v", err)
	}
}

func TestWritePrivateFileIsUserOnlyAndReadRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "secrets.envault")
	body := []byte("encrypted-body\n")
	if err := transfer.WritePrivateFile(path, body); err != nil {
		t.Fatal(err)
	}
	if err := transfer.WritePrivateFile(path, []byte("replaced-body\n")); err != nil {
		t.Fatal(err)
	}
	got, err := transfer.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "replaced-body\n" {
		t.Fatalf("ReadFile() = %q", got)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %o, want 600", info.Mode().Perm())
		}
	}
	matches, err := filepath.Glob(filepath.Join(dir, "nested", ".envvault-export-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temp files left behind: %v", matches)
	}

	link := filepath.Join(dir, "link.envault")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	_, err = transfer.ReadFile(link)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink error = %v", err)
	}

	huge := filepath.Join(dir, "huge.envault")
	handle, err := os.Create(huge)
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Truncate((8 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	handle.Close()
	_, err = transfer.ReadFile(huge)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("large file error = %v", err)
	}
}

func baseConfig(installationID string) config.File {
	return config.File{
		Version:      1,
		Installation: config.Installation{ID: installationID},
		Runtime: config.Runtime{Talos: config.TalosRuntime{
			Mode:      "managed",
			Version:   "test-talos",
			Lifecycle: "on-demand",
		}},
		Defaults: config.Defaults{
			TokenTTL:    config.Duration(10 * time.Minute),
			MaxTokenTTL: config.Duration(time.Hour),
		},
		Profiles: map[string]config.Profile{},
	}
}

func namesOnly(bundle transfer.Bundle) []string {
	names := make([]string, 0, len(bundle.Credentials))
	for _, credential := range bundle.Credentials {
		names = append(names, credential.Name)
	}
	return names
}

func tamperCiphertext(t *testing.T, file []byte) []byte {
	t.Helper()
	env := decodeEnvelope(t, file)
	raw, err := base64.StdEncoding.DecodeString(env["ciphertext"].(string))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x5a
	env["ciphertext"] = base64.StdEncoding.EncodeToString(raw)
	return marshalEnvelope(t, env)
}

func tamperNonce(t *testing.T, file []byte) []byte {
	t.Helper()
	env := decodeEnvelope(t, file)
	nonce := env["nonce"].(string)
	if nonce[0] == 'A' {
		nonce = "B" + nonce[1:]
	} else {
		nonce = "A" + nonce[1:]
	}
	env["nonce"] = nonce
	return marshalEnvelope(t, env)
}

func replaceJSONField(t *testing.T, file []byte, key string, value any) []byte {
	t.Helper()
	env := decodeEnvelope(t, file)
	env[key] = value
	return marshalEnvelope(t, env)
}

func decodeEnvelope(t *testing.T, file []byte) map[string]any {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal(file, &env); err != nil {
		t.Fatal(err)
	}
	return env
}

func marshalEnvelope(t *testing.T, env map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
