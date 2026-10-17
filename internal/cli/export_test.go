package cli_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/trknhr/envvault/internal/cli"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/transfer"
)

func TestRunExportImportRoundTrip(t *testing.T) {
	ctx := context.Background()
	sourcePaths := testPaths(t)
	writeBaseConfig(t, sourcePaths)
	sourceCfg, err := config.Load(sourcePaths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	sourceCfg.AddCredential("database/dev")
	sourceCfg.Profiles["app/dev"] = config.Profile{
		Kind:           profile.KindInject,
		CredentialName: "database/dev",
		ProjectBinding: config.ProjectBinding{Mode: profile.ProjectBindingNone},
	}
	if err := config.Save(sourcePaths.ConfigFile, sourceCfg); err != nil {
		t.Fatal(err)
	}
	sourceSecrets := keyring.NewMemoryStore()
	secret := []byte("envvault-secret-canary-9f3a\n\x00\xff")
	if err := sourceSecrets.Put(ctx, keyring.CredentialValue("database/dev"), secret); err != nil {
		t.Fatal(err)
	}
	if err := sourceSecrets.Put(ctx, keyring.TalosHMACKey(), []byte("talos-hmac-canary")); err != nil {
		t.Fatal(err)
	}
	if err := sourceSecrets.Put(ctx, keyring.ProfileParentKey("app/dev"), []byte("parent-key-canary")); err != nil {
		t.Fatal(err)
	}
	exportPath := filepath.Join(t.TempDir(), "secrets.envault")
	first := []byte("export-passphrase")
	second := []byte("export-passphrase")
	source := cli.New(cli.Options{
		Paths:     sourcePaths,
		Secrets:   sourceSecrets,
		ExportKDF: transfer.TestKDFParams(),
		PassphraseReader: func(output io.Writer, prompt string) ([]byte, error) {
			if _, err := io.WriteString(output, prompt); err != nil {
				return nil, err
			}
			if strings.HasPrefix(prompt, "Confirm ") {
				return second, nil
			}
			return first, nil
		},
	})
	var stdout, stderr bytes.Buffer
	code := source.Run(ctx, []string{"export", exportPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("export code = %d, stderr=%q", code, stderr.String())
	}
	if stdout.String() != "exported credential database/dev\nexported profile app/dev\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.String() != "Export passphrase: Confirm export passphrase: " {
		t.Fatalf("stderr = %q", stderr.String())
	}
	for _, buf := range [][]byte{first, second} {
		for i, b := range buf {
			if b != 0 {
				t.Fatalf("passphrase byte %d was not cleared", i)
			}
		}
	}
	file, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, hidden := range [][]byte{secret, []byte("export-passphrase"), []byte("talos-hmac-canary"), []byte("parent-key-canary")} {
		if bytes.Contains(file, hidden) {
			t.Fatalf("export file leaked %q", hidden)
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(exportPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %o, want 600", info.Mode().Perm())
		}
	}

	destPaths := testPaths(t)
	writeBaseConfig(t, destPaths)
	destSecrets := keyring.NewMemoryStore()
	importPass := []byte("export-passphrase")
	dest := cli.New(cli.Options{
		Paths:     destPaths,
		Secrets:   destSecrets,
		ExportKDF: transfer.TestKDFParams(),
		PassphraseReader: func(output io.Writer, prompt string) ([]byte, error) {
			_, err := io.WriteString(output, prompt)
			return importPass, err
		},
	})
	stdout.Reset()
	stderr.Reset()
	code = dest.Run(ctx, []string{"import", exportPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("import code = %d, stderr=%q", code, stderr.String())
	}
	if stdout.String() != "imported credential database/dev\nimported profile app/dev\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.String() != "Import passphrase: " {
		t.Fatalf("stderr = %q", stderr.String())
	}
	for i, b := range importPass {
		if b != 0 {
			t.Fatalf("import passphrase byte %d was not cleared", i)
		}
	}
	got, err := destSecrets.Get(ctx, keyring.CredentialValue("database/dev"))
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("imported = %q, error = %v", got, err)
	}
	if _, err := destSecrets.Get(ctx, keyring.TalosHMACKey()); err == nil {
		t.Fatal("import stored a Talos key")
	}
	if _, err := destSecrets.Get(ctx, keyring.ProfileParentKey("app/dev")); err == nil {
		t.Fatal("import stored a parent key")
	}
	destCfg, err := config.Load(destPaths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if destCfg.Installation.ID != "01JTESTINSTALL" || destCfg.Profiles["app/dev"].CredentialName != "database/dev" {
		t.Fatalf("dest config = %#v", destCfg)
	}
	if strings.Join(destCfg.CredentialNames(), ",") != "database/dev" {
		t.Fatalf("credentials = %#v", destCfg.CredentialNames())
	}
}

func TestRunImportSkipsConflictsUnlessOverwrite(t *testing.T) {
	ctx := context.Background()
	paths := testPaths(t)
	writeBaseConfig(t, paths)
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AddCredential("database/dev")
	cfg.Profiles["app/dev"] = config.Profile{
		Kind:           profile.KindInject,
		CredentialName: "database/dev",
		ProjectBinding: config.ProjectBinding{Mode: profile.ProjectBindingNone},
	}
	if err := config.Save(paths.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue("database/dev"), []byte("dest-secret-canary")); err != nil {
		t.Fatal(err)
	}
	file := exportFixture(t, "file-secret-canary", "sha256:moved")
	app := newTransferApp(t, paths, secrets, strings.NewReader("export-passphrase\n"))

	var stdout, stderr bytes.Buffer
	code := app.Run(ctx, []string{"import", file, "--passphrase-stdin"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("import code = %d, stderr=%q", code, stderr.String())
	}
	if stdout.String() != "skipped credential database/dev\nskipped profile app/dev\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	got, err := secrets.Get(ctx, keyring.CredentialValue("database/dev"))
	if err != nil || string(got) != "dest-secret-canary" {
		t.Fatalf("stored = %q, error = %v", got, err)
	}
	cfg, err = config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profiles["app/dev"].ProjectBinding.PathHash != "" {
		t.Fatalf("skip wrote binding %#v", cfg.Profiles["app/dev"].ProjectBinding)
	}
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, "dest-secret-canary") || strings.Contains(combined, "file-secret-canary") || strings.Contains(combined, "export-passphrase") {
		t.Fatalf("output leaked secret material: %q", combined)
	}

	stdout.Reset()
	stderr.Reset()
	app = newTransferApp(t, paths, secrets, strings.NewReader("export-passphrase\n"))
	code = app.Run(ctx, []string{"import", file, "--passphrase-stdin", "--overwrite"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("overwrite code = %d, stderr=%q", code, stderr.String())
	}
	if stdout.String() != "replaced credential database/dev\nreplaced profile app/dev\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	got, err = secrets.Get(ctx, keyring.CredentialValue("database/dev"))
	if err != nil || string(got) != "file-secret-canary" {
		t.Fatalf("replaced = %q, error = %v", got, err)
	}
	cfg, err = config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profiles["app/dev"].ProjectBinding.PathHash != "sha256:moved" {
		t.Fatalf("binding = %#v", cfg.Profiles["app/dev"].ProjectBinding)
	}
}

func TestRunImportRejectsWrongPassphraseAndTampering(t *testing.T) {
	ctx := context.Background()
	paths := testPaths(t)
	writeBaseConfig(t, paths)
	secrets := keyring.NewMemoryStore()
	file := exportFixture(t, "envvault-secret-canary-9f3a", "")
	app := newTransferApp(t, paths, secrets, strings.NewReader("wrong-passphrase\n"))
	var stdout, stderr bytes.Buffer

	code := app.Run(ctx, []string{"import", file, "--passphrase-stdin"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "wrong passphrase") {
		t.Fatalf("code = %d, stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "envvault-secret-canary-9f3a") || strings.Contains(stderr.String(), "wrong-passphrase") {
		t.Fatalf("output leaked secret material: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if _, err := secrets.Get(ctx, keyring.CredentialValue("database/dev")); err == nil {
		t.Fatal("wrong passphrase stored a credential")
	}

	tamperExportCiphertext(t, file)
	stdout.Reset()
	stderr.Reset()
	app = newTransferApp(t, paths, secrets, strings.NewReader("export-passphrase\n"))
	code = app.Run(ctx, []string{"import", file, "--passphrase-stdin"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "export file was tampered with") {
		t.Fatalf("code = %d, stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "envvault-secret-canary-9f3a") {
		t.Fatalf("tamper output leaked secret: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunExportImportRejectsBadPassphrasesAndMissingState(t *testing.T) {
	ctx := context.Background()
	paths := testPaths(t)
	writeBaseConfig(t, paths)
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue("database/dev"), []byte("envvault-secret-canary-9f3a")); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AddCredential("database/dev")
	if err := config.Save(paths.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	exportPath := filepath.Join(t.TempDir(), "secrets.envault")

	var stdout, stderr bytes.Buffer
	app := newTransferApp(t, paths, secrets, strings.NewReader("one\ntwo\n"))
	code := app.Run(ctx, []string{"export", exportPath, "--passphrase-stdin"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "at least 8 characters") {
		t.Fatalf("short passphrase code = %d, stderr=%q", code, stderr.String())
	}
	if _, err := os.Stat(exportPath); !os.IsNotExist(err) {
		t.Fatalf("export file err = %v, want missing", err)
	}

	stdout.Reset()
	stderr.Reset()
	mismatch := cli.New(cli.Options{
		Paths:     paths,
		Secrets:   secrets,
		ExportKDF: transfer.TestKDFParams(),
		PassphraseReader: func(output io.Writer, prompt string) ([]byte, error) {
			if strings.HasPrefix(prompt, "Confirm ") {
				return []byte("second-passphrase"), nil
			}
			return []byte("first-passphrase"), nil
		},
	})
	code = mismatch.Run(ctx, []string{"export", exportPath}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "passphrases do not match") {
		t.Fatalf("mismatch code = %d, stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "first-passphrase") || strings.Contains(stdout.String()+stderr.String(), "second-passphrase") {
		t.Fatalf("mismatch leaked passphrase: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = cli.New(cli.Options{Paths: paths, Secrets: secrets, ExportKDF: transfer.TestKDFParams()}).Run(ctx, []string{"export", exportPath}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "--passphrase-stdin") {
		t.Fatalf("missing reader code = %d, stderr=%q", code, stderr.String())
	}

	emptyPaths := testPaths(t)
	stdout.Reset()
	stderr.Reset()
	code = newTransferApp(t, emptyPaths, keyring.NewMemoryStore(), strings.NewReader("export-passphrase\n")).Run(ctx, []string{"export", exportPath, "--passphrase-stdin"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "nothing to export") {
		t.Fatalf("empty export code = %d, stderr=%q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = newTransferApp(t, emptyPaths, keyring.NewMemoryStore(), strings.NewReader("export-passphrase\n")).Run(ctx, []string{"import", exportPath, "--passphrase-stdin"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "run envvault init before import") {
		t.Fatalf("missing init code = %d, stderr=%q", code, stderr.String())
	}
}

func TestRunExportImportHelpDoesNotOfferPassphraseFlag(t *testing.T) {
	app := cli.New(cli.Options{})
	for _, args := range [][]string{
		{"export", "--help"},
		{"import", "--help"},
	} {
		var stdout, stderr bytes.Buffer
		code := app.Run(context.Background(), args, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("%v code = %d, stderr=%q", args, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "--passphrase-stdin") {
			t.Fatalf("%v help missing stdin flag:\n%s", args, stdout.String())
		}
		if strings.Contains(stdout.String(), "--passphrase ") || strings.Contains(stdout.String(), "--passphrase\n") {
			t.Fatalf("%v help offered a passphrase value flag:\n%s", args, stdout.String())
		}
	}
	var stdout, stderr bytes.Buffer
	code := app.Run(context.Background(), []string{"import", "--help"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "--overwrite") {
		t.Fatalf("import help = %q, stderr=%q", stdout.String(), stderr.String())
	}
}

func newTransferApp(t *testing.T, paths config.Paths, secrets keyring.Store, stdin io.Reader) cli.App {
	t.Helper()
	return cli.New(cli.Options{
		Paths:     paths,
		Secrets:   secrets,
		Stdin:     stdin,
		ExportKDF: transfer.TestKDFParams(),
	})
}

func exportFixture(t *testing.T, secret, pathHash string) string {
	t.Helper()
	ctx := context.Background()
	paths := testPaths(t)
	writeBaseConfig(t, paths)
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AddCredential("database/dev")
	binding := config.ProjectBinding{Mode: profile.ProjectBindingNone}
	if pathHash != "" {
		binding = config.ProjectBinding{Mode: profile.ProjectBindingPathHash, PathHash: pathHash}
	}
	cfg.Profiles["app/dev"] = config.Profile{
		Kind:           profile.KindInject,
		CredentialName: "database/dev",
		ProjectBinding: binding,
	}
	if err := config.Save(paths.ConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue("database/dev"), []byte(secret)); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "secrets.envault")
	app := newTransferApp(t, paths, secrets, strings.NewReader("export-passphrase\n"))
	var stdout, stderr bytes.Buffer
	code := app.Run(ctx, []string{"export", file, "--passphrase-stdin"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("fixture export code = %d, stderr=%q", code, stderr.String())
	}
	return file
}

func tamperExportCiphertext(t *testing.T, path string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(env["ciphertext"].(string))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x5a
	env["ciphertext"] = base64.StdEncoding.EncodeToString(raw)
	updated, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(updated, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
