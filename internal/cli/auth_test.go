package cli_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/trknhr/envvault/internal/authstate"
	"github.com/trknhr/envvault/internal/cli"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/keyring"
)

func TestHostGitHubCLILoginUsesDisposableHomeAndEncryptsToken(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture executable")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git is required for the credential-helper isolation check")
	}
	_, paths, secrets := authApp(t, "")
	bin := t.TempDir()
	// A fixture CLI checks that inherited tokens and the operator home are absent.
	script := `#!/bin/sh
set -eu
test -z "${GH_TOKEN:-}${GITHUB_TOKEN:-}${GH_DEBUG:-}"
test -z "${GIT_CONFIG_PARAMETERS:-}${GIT_CONFIG_COUNT:-}${GIT_DIR:-}${GIT_WORK_TREE:-}${GIT_EXEC_PATH:-}"
case "$HOME" in */.github-login-*) ;; *) exit 1 ;; esac
test "$GIT_CONFIG_NOSYSTEM" = 1
test "$GIT_CONFIG_SYSTEM" = /dev/null
test "$GIT_CONFIG_GLOBAL" = "$HOME/gitconfig"
test "$(git config --get-urlmatch credential.helper https://github.com)" = '!gh auth git-credential'
test "$(git config --show-origin --get credential.https://github.com.helper | cut -f1)" = "file:$HOME/gitconfig"
case "$1 $2" in
  'auth login')
    case " $* " in *' --insecure-storage '*) ;; *) exit 1 ;; esac
    mkdir -p "$GH_CONFIG_DIR"; printf 'temporary login\n' > "$GH_CONFIG_DIR/hosts.yml" ;;
  'auth token') printf 'host-gh-canary\n' ;;
  *) exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GH_TOKEN", "inherited-canary")
	t.Setenv("GITHUB_TOKEN", "inherited-canary")
	t.Setenv("GH_DEBUG", "api")
	t.Setenv("GIT_CONFIG_PARAMETERS", "'credential.helper'='unwanted-host-helper'")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "credential.helper")
	t.Setenv("GIT_CONFIG_VALUE_0", "unwanted-host-helper")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), "operator-gitconfig"))
	t.Setenv("GIT_CONFIG_SYSTEM", filepath.Join(t.TempDir(), "operator-system-gitconfig"))
	t.Setenv("GIT_DIR", t.TempDir())
	t.Setenv("GIT_WORK_TREE", t.TempDir())
	t.Setenv("GIT_EXEC_PATH", t.TempDir())
	app := cli.New(cli.Options{Paths: paths, Secrets: secrets, Stdin: strings.NewReader("")})
	var out, stderr bytes.Buffer
	if code := app.Run(context.Background(), []string{"auth", "login", "github", "--name", "github/cli"}, &out, &stderr); code != 0 {
		t.Fatalf("host CLI login failed: %s", &stderr)
	}
	if strings.Contains(out.String()+stderr.String(), "canary") {
		t.Fatal("host CLI login printed a token")
	}
	entries, _ := os.ReadDir(paths.DataDir)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".github-login-") {
			t.Fatal("temporary host login directory remained")
		}
	}
	cfg, _ := config.Load(paths.ConfigFile)
	record, err := (authstate.Store{Dir: filepath.Join(paths.DataDir, "auth-profiles"), Keys: secrets}).Read(context.Background(), cfg.AuthProfiles["github/cli"])
	if err != nil {
		t.Fatal(err)
	}
	defer record.Zero()
	value, err := authstate.Token(record.Document, "/access_token")
	defer keyring.Zero(value)
	if err != nil || string(value) != "host-gh-canary" {
		t.Fatal("host token was not encrypted correctly")
	}
}

type authRoundTrip func(*http.Request) (*http.Response, error)

func (f authRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAuthLoginDeviceFlowStoresRefreshStateOnlyOnHost(t *testing.T) {
	_, paths, secrets := authApp(t, "")
	app := cli.New(cli.Options{Paths: paths, Secrets: secrets, AuthHTTP: &http.Client{Transport: authRoundTrip(func(r *http.Request) (*http.Response, error) {
		body := `{"device_code":"private-device-canary","user_code":"TEST-CODE","verification_uri":"https://github.com/login/device","interval":1,"expires_in":60}`
		if r.URL.Path == "/login/oauth/access_token" {
			body = `{"access_token":"access-canary","refresh_token":"refresh-canary","expires_in":3600}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}})
	var out, stderr bytes.Buffer
	if code := app.Run(context.Background(), []string{"auth", "login", "github", "--name", "github/work", "--client-id", "own-public-client"}, &out, &stderr); code != 0 {
		t.Fatalf("device login failed: %s", &stderr)
	}
	if strings.Contains(out.String()+stderr.String(), "canary") || !strings.Contains(stderr.String(), "TEST-CODE") {
		t.Fatal("device authorization printed private state or omitted approval code")
	}
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	record, err := (authstate.Store{Dir: filepath.Join(paths.DataDir, "auth-profiles"), Keys: secrets}).Read(context.Background(), cfg.AuthProfiles["github/work"])
	if err != nil {
		t.Fatal(err)
	}
	defer record.Zero()
	if record.Metadata.RefreshField != "/refresh_token" || record.Metadata.ExpiresField != "/expires_at" || record.Metadata.ClientID != "own-public-client" {
		t.Fatal("login discarded refresh metadata")
	}
}

func TestGitRepositoryProxyFlagsStoreReadOnlyScopeByDefault(t *testing.T) {
	app, paths, _ := authApp(t, "")
	var out, stderr bytes.Buffer
	if code := app.Run(context.Background(), []string{"proxy", "add", "github-git", "--credential", "github/work", "--git-repository", "owner/repo", "--project-binding", "none"}, &out, &stderr); code != 0 {
		t.Fatalf("Git profile failed: %s", &stderr)
	}
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Profiles["github-git"]
	if p.TargetURL != "https://github.com" || len(p.AllowedPaths) != 4 {
		t.Fatal("Git read scope was not saved")
	}
	for _, path := range p.AllowedPaths {
		if strings.HasSuffix(path, "/git-receive-pack") {
			t.Fatal("Git profile granted push by default")
		}
	}
}

func authApp(t *testing.T, input string) (cli.App, config.Paths, keyring.Store) {
	t.Helper()
	root := t.TempDir()
	paths := config.Paths{ConfigFile: filepath.Join(root, "config.yaml"), DataDir: filepath.Join(root, "data"), CacheDir: filepath.Join(root, "cache")}
	secrets := keyring.NewMemoryStore()
	return cli.New(cli.Options{Paths: paths, Secrets: secrets, Stdin: strings.NewReader(input)}), paths, secrets
}

func TestAuthImportListOverwriteAndLogoutNeverPrintValues(t *testing.T) {
	ctx := context.Background()
	app, paths, secrets := authApp(t, `{"tokens":{"access":"structured-canary","refresh":"refresh-canary"}}`)
	var out, stderr bytes.Buffer
	if code := app.Run(ctx, []string{"auth", "import", "service/work", "--file", "-", "--token-field", "/tokens/access"}, &out, &stderr); code != 0 {
		t.Fatalf("import failed: %s", &stderr)
	}
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil || cfg.Version != 2 || len(cfg.AuthProfiles) != 1 {
		t.Fatal("authentication metadata was not versioned")
	}
	store := authstate.Store{Dir: filepath.Join(paths.DataDir, "auth-profiles"), Keys: secrets}
	record, err := store.Read(ctx, cfg.AuthProfiles["service/work"])
	if err != nil {
		t.Fatal(err)
	}
	defer record.Zero()
	for _, args := range [][]string{{"auth", "list"}, {"auth", "status", "service/work"}, {"credential", "list"}} {
		out.Reset()
		stderr.Reset()
		if code := app.Run(ctx, args, &out, &stderr); code != 0 || !strings.Contains(out.String(), "service/work") || strings.Contains(out.String()+stderr.String(), "canary") {
			t.Fatal("metadata command failed or leaked a value")
		}
	}
	file := filepath.Join(t.TempDir(), "auth.yaml")
	os.WriteFile(file, []byte("token: replacement-canary\n"), 0600)
	if code := app.Run(ctx, []string{"auth", "import", "service/work", "--file", file, "--token-field", "/token"}, &out, &stderr); code == 0 {
		t.Fatal("import overwrote without explicit selection")
	}
	if code := app.Run(ctx, []string{"auth", "import", "service/work", "--file", file, "--token-field", "/token", "--overwrite"}, &out, &stderr); code != 0 {
		t.Fatalf("replacement failed: %s", &stderr)
	}
	if code := app.Run(ctx, []string{"auth", "logout", "service/work"}, &out, &stderr); code != 0 {
		t.Fatalf("logout failed: %s", &stderr)
	}
	if _, err := store.Read(ctx, record.Metadata.ID); err == nil {
		t.Fatal("logout left a usable decryption key")
	}
	if strings.Contains(out.String()+stderr.String(), "canary") {
		t.Fatal("CLI printed authentication material")
	}
}

func TestAuthImportRollsBackWhenConfigurationCannotCommit(t *testing.T) {
	_, paths, secrets := authApp(t, "")
	app := cli.New(cli.Options{Paths: paths, Secrets: secrets, Stdin: strings.NewReader(`{"access_token":"rollback-canary"}`), ConfigSaver: func(string, config.File) error { return errors.New("private failure") }})
	var out, stderr bytes.Buffer
	if code := app.Run(context.Background(), []string{"auth", "import", "work", "--file", "-"}, &out, &stderr); code == 0 {
		t.Fatal("failed config commit reported success")
	}
	entries, _ := os.ReadDir(filepath.Join(paths.DataDir, "auth-profiles"))
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			t.Fatal("failed config commit left a live auth record")
		}
	}
	if strings.Contains(stderr.String(), "rollback-canary") || strings.Contains(stderr.String(), "private failure") {
		t.Fatal("failure diagnostics were not redacted")
	}
}
