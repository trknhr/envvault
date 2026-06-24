package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/credlease/internal/bootstrap"
	"github.com/trknhr/credlease/internal/browser"
	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/cli"
	"github.com/trknhr/credlease/internal/config"
	"github.com/trknhr/credlease/internal/doctor"
	"github.com/trknhr/credlease/internal/issuer"
	"github.com/trknhr/credlease/internal/process"
	"github.com/trknhr/credlease/internal/profile"
	"github.com/trknhr/credlease/internal/profilemgr"
	"github.com/trknhr/credlease/internal/projectbinding"
	resetpkg "github.com/trknhr/credlease/internal/reset"
)

func TestRunRequiresCommand(t *testing.T) {
	var stderr bytes.Buffer

	code := cli.Run(nil, new(bytes.Buffer), &stderr)

	if code != 2 {
		t.Fatalf("Run() code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "command required") {
		t.Fatalf("stderr = %q, want command required", stderr.String())
	}
}

func TestRunCompletionBashWritesCommandsWithoutServices(t *testing.T) {
	app := cli.New(cli.Options{})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"completion", "bash"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	for _, want := range []string{
		"# bash completion for credlease",
		"complete -F _credlease credlease",
		"init reset doctor profile token exec open jwks issuer completion",
		"--repair",
		"browser-session",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
	if strings.Contains(stdout.String(), "secret-canary") || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want no secret and empty stderr", stdout.String(), stderr.String())
	}
}

func TestRunCompletionZshFishAndPowerShell(t *testing.T) {
	for _, shell := range []string{"zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			app := cli.New(cli.Options{})
			var stdout, stderr bytes.Buffer

			code := app.Run(context.Background(), []string{"completion", shell}, &stdout, &stderr)

			if code != 0 {
				t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
			}
			for _, want := range []string{"credlease", "doctor", "profile", "completion"} {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("stdout = %q, want %q", stdout.String(), want)
				}
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}
		})
	}
}

func TestRunCompletionRejectsUnknownShell(t *testing.T) {
	app := cli.New(cli.Options{})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"completion", "tcsh"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("Run() code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage: credlease completion <bash|zsh|fish|powershell>") {
		t.Fatalf("stderr = %q, want completion usage", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRunInitCallsInitializer(t *testing.T) {
	paths := testPaths(t)
	initializer := &fakeInitializer{result: bootstrap.Result{
		ConfigPath: paths.ConfigFile,
		SQLitePath: filepath.Join(paths.DataDir, "credlease.sqlite"),
		JWKSPath:   filepath.Join(paths.DataDir, "credlease-jwks.json"),
	}}
	app := cli.New(cli.Options{
		Paths:       paths,
		Initializer: initializer,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"init"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if initializer.calls != 1 {
		t.Fatalf("initializer calls = %d, want 1", initializer.calls)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want both empty", stdout.String(), stderr.String())
	}
}

func TestRunInitReturnsErrorWithoutLeakingSecret(t *testing.T) {
	initializer := &fakeInitializer{
		err: clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable"),
	}
	app := cli.New(cli.Options{
		Paths:       testPaths(t),
		Initializer: initializer,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"init"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "CREDLEASE_KEYRING_UNAVAILABLE") {
		t.Fatalf("stderr = %q, want keyring error code", stderr.String())
	}
	if strings.Contains(stderr.String(), "secret-canary") {
		t.Fatalf("stderr leaked secret marker: %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRunExecRejectsInvalidInlineEnvReference(t *testing.T) {
	var stderr bytes.Buffer

	code := cli.Run([]string{
		"exec",
		"--env", "TOKEN=credlease://backend-a/dev?scope=admin",
		"--", "inspect-child",
	}, new(bytes.Buffer), &stderr)

	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "CREDLEASE_REFERENCE_INVALID") {
		t.Fatalf("stderr = %q, want reference error code", stderr.String())
	}
	if strings.Contains(stderr.String(), "scope=admin") {
		t.Fatalf("stderr leaked rejected reference: %q", stderr.String())
	}
}

func TestRunExecReturnsNotImplementedForValidInlineEnvReferenceWhenExecUnavailable(t *testing.T) {
	app := cli.New(cli.Options{})
	var stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"exec",
		"--env=TOKEN=credlease://backend-a/dev",
		"--", "inspect-child",
	}, new(bytes.Buffer), &stderr)

	if code != 2 {
		t.Fatalf("Run() code = %d, want 2", code)
	}
	if strings.Contains(stderr.String(), "CREDLEASE_REFERENCE_INVALID") {
		t.Fatalf("stderr = %q, did not expect reference error", stderr.String())
	}
	if !strings.Contains(stderr.String(), "not implemented") {
		t.Fatalf("stderr = %q, want not implemented", stderr.String())
	}
}

func TestRunExecResolvesEnvAndRunsChild(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envFile, []byte("TOKEN=credlease://backend-a/dev\nPLAIN=file-value\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	issuer := &fakeTokenIssuer{}
	runner := &fakeChildRunner{code: 42}
	app := cli.New(cli.Options{
		Paths:     testPaths(t),
		ParentEnv: []string{"TOKEN=raw-parent-secret", "HOME=/tmp/home"},
		Profiles:  fakeCLIProfiles(),
		Issuer:    issuer,
		Runner:    runner,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"exec",
		"--env-file", envFile,
		"--env", "INLINE=inline-value",
		"--", "inspect-child", "arg",
	}, &stdout, &stderr)

	if code != 42 {
		t.Fatalf("Run() code = %d, want child code 42; stderr=%q", code, stderr.String())
	}
	if got, want := runner.input.Command, []string{"inspect-child", "arg"}; strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("command = %#v, want %#v", got, want)
	}
	if got := runner.input.Env["TOKEN"]; got != "jwt-for-backend-a/dev" {
		t.Fatalf("TOKEN = %q, want issued token", got)
	}
	if got := runner.input.Env["PLAIN"]; got != "file-value" {
		t.Fatalf("PLAIN = %q, want file value", got)
	}
	if got := runner.input.Env["INLINE"]; got != "inline-value" {
		t.Fatalf("INLINE = %q, want inline value", got)
	}
	if got := runner.input.Env["HOME"]; got != "/tmp/home" {
		t.Fatalf("HOME = %q, want parent env value", got)
	}
	if len(issuer.grants) != 1 {
		t.Fatalf("issuer grants = %d, want 1", len(issuer.grants))
	}
	if strings.Contains(stderr.String(), "raw-parent-secret") {
		t.Fatalf("stderr leaked parent secret: %q", stderr.String())
	}
}

func TestRunExecUsesProjectIdentityForApprovedBinding(t *testing.T) {
	root := t.TempDir()
	envFile := filepath.Join(root, ".env")
	if err := os.WriteFile(envFile, []byte("TOKEN=credlease://backend-a/dev\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	profiles := fakeCLIProfiles()
	p := profiles["backend-a/dev"]
	binding, err := projectbinding.Approve(profile.ProjectBindingPathHash, projectbinding.Identity{Root: root})
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	p.ProjectBinding = binding
	profiles["backend-a/dev"] = p
	issuer := &fakeTokenIssuer{}
	runner := &fakeChildRunner{}
	app := cli.New(cli.Options{
		ProjectStartDir: root,
		Profiles:        profiles,
		Issuer:          issuer,
		Runner:          runner,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"exec", "--env-file", envFile, "--", "child"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if runner.input.Env["TOKEN"] != "jwt-for-backend-a/dev" {
		t.Fatalf("TOKEN = %q, want issued token", runner.input.Env["TOKEN"])
	}
	if len(issuer.grants) != 1 {
		t.Fatalf("issuer grants = %d, want 1", len(issuer.grants))
	}
}

func TestRunExecProvidesSignalChannelToRunner(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envFile, []byte("TOKEN=credlease://backend-a/dev\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	runner := &fakeChildRunner{}
	app := cli.New(cli.Options{
		Profiles: fakeCLIProfiles(),
		Issuer:   &fakeTokenIssuer{},
		Runner:   runner,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"exec", "--env-file", envFile, "--", "child"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if runner.input.Signals == nil {
		t.Fatal("RunInput.Signals = nil, want signal forwarding channel")
	}
}

func TestRunTokenWritesRawLeasedToken(t *testing.T) {
	expiresAt := time.Date(2026, 6, 22, 12, 10, 0, 0, time.UTC)
	tokenIssuer := &fakeTokenIssuer{credential: issuer.Credential{
		AccessToken: "leased-jwt",
		TokenType:   "Bearer",
		ExpiresAt:   expiresAt,
		Scopes:      []string{"repository:read"},
	}}
	app := cli.New(cli.Options{
		Paths:    testPaths(t),
		Profiles: fakeCLIProfiles(),
		Issuer:   tokenIssuer,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"token", "backend-a/dev"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if got, want := stdout.String(), "leased-jwt\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	assertTokenGrant(t, tokenIssuer.grants[0])
}

func TestRunTokenWritesJSONLeasedToken(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	tokenIssuer := &fakeTokenIssuer{credential: issuer.Credential{
		AccessToken: "leased-jwt",
		TokenType:   "Bearer",
		ExpiresAt:   now.Add(10 * time.Minute),
		Scopes:      []string{"repository:read"},
	}}
	app := cli.New(cli.Options{
		Paths:    testPaths(t),
		Profiles: fakeCLIProfiles(),
		Issuer:   tokenIssuer,
		Now:      func() time.Time { return now },
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"token", "backend-a/dev", "--format", "json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; stdout=%q", err, stdout.String())
	}
	for key, want := range map[string]any{
		"access_token": "leased-jwt",
		"token_type":   "Bearer",
		"expires_at":   "2026-06-22T12:10:00Z",
		"expires_in":   float64(600),
		"profile":      "backend-a/dev",
		"resource":     "https://api.dev.example.com",
	} {
		if got[key] != want {
			t.Fatalf("%s = %#v, want %#v", key, got[key], want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	assertTokenGrant(t, tokenIssuer.grants[0])
}

func TestRunTokenRejectsRawTTYOutputWithoutOptInBeforeIssuing(t *testing.T) {
	tokenIssuer := &fakeTokenIssuer{}
	app := cli.New(cli.Options{
		Profiles:         fakeCLIProfiles(),
		Issuer:           tokenIssuer,
		StdoutIsTerminal: func() bool { return true },
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"token", "backend-a/dev"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "--allow-tty") {
		t.Fatalf("stderr = %q, want --allow-tty guidance", stderr.String())
	}
	if strings.Contains(stderr.String(), "leased-jwt") || strings.Contains(stderr.String(), "jwt-for-backend-a/dev") {
		t.Fatalf("stderr leaked token: %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if len(tokenIssuer.grants) != 0 {
		t.Fatalf("issuer grants = %d, want 0", len(tokenIssuer.grants))
	}
}

func TestRunTokenAllowTTYWritesWarningAndToken(t *testing.T) {
	tokenIssuer := &fakeTokenIssuer{credential: issuer.Credential{
		AccessToken: "leased-jwt",
		TokenType:   "Bearer",
		ExpiresAt:   time.Date(2026, 6, 22, 12, 10, 0, 0, time.UTC),
		Scopes:      []string{"repository:read"},
	}}
	app := cli.New(cli.Options{
		Profiles:         fakeCLIProfiles(),
		Issuer:           tokenIssuer,
		StdoutIsTerminal: func() bool { return true },
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"token", "backend-a/dev", "--allow-tty"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if got, want := stdout.String(), "leased-jwt\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if !strings.Contains(stderr.String(), "warning") {
		t.Fatalf("stderr = %q, want warning", stderr.String())
	}
	if strings.Contains(stderr.String(), "leased-jwt") {
		t.Fatalf("stderr leaked token: %q", stderr.String())
	}
	if len(tokenIssuer.grants) != 1 {
		t.Fatalf("issuer grants = %d, want 1", len(tokenIssuer.grants))
	}
}

func TestRunTokenQuietAllowsTTYWithoutWarning(t *testing.T) {
	tokenIssuer := &fakeTokenIssuer{credential: issuer.Credential{
		AccessToken: "leased-jwt",
		TokenType:   "Bearer",
		ExpiresAt:   time.Date(2026, 6, 22, 12, 10, 0, 0, time.UTC),
		Scopes:      []string{"repository:read"},
	}}
	app := cli.New(cli.Options{
		Profiles:         fakeCLIProfiles(),
		Issuer:           tokenIssuer,
		StdoutIsTerminal: func() bool { return true },
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"token", "backend-a/dev", "--quiet"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if got, want := stdout.String(), "leased-jwt\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunTokenRejectsUnapprovedProjectBindingBeforeIssuing(t *testing.T) {
	approvedRoot := filepath.Join(t.TempDir(), "approved")
	binding, err := projectbinding.Approve(profile.ProjectBindingPathHash, projectbinding.Identity{Root: approvedRoot})
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	profiles := fakeCLIProfiles()
	p := profiles["backend-a/dev"]
	p.ProjectBinding = binding
	profiles["backend-a/dev"] = p
	tokenIssuer := &fakeTokenIssuer{}
	app := cli.New(cli.Options{
		ProjectStartDir: filepath.Join(t.TempDir(), "other"),
		Profiles:        profiles,
		Issuer:          tokenIssuer,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"token", "backend-a/dev"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), string(clerr.ProjectNotTrusted)) {
		t.Fatalf("stderr = %q, want project binding error", stderr.String())
	}
	if len(tokenIssuer.grants) != 0 {
		t.Fatalf("issuer grants = %d, want 0", len(tokenIssuer.grants))
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRunTokenGrantIncludesProjectClaims(t *testing.T) {
	projectRoot := filepath.Join(t.TempDir(), "repo")
	wantProjectID, err := projectbinding.PathHash(projectRoot)
	if err != nil {
		t.Fatalf("PathHash() error = %v", err)
	}
	tokenIssuer := &fakeTokenIssuer{}
	app := cli.New(cli.Options{
		ProjectStartDir: projectRoot,
		Profiles:        fakeCLIProfiles(),
		Issuer:          tokenIssuer,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"token", "backend-a/dev"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if len(tokenIssuer.grants) != 1 {
		t.Fatalf("issuer grants = %d, want 1", len(tokenIssuer.grants))
	}
	claims := tokenIssuer.grants[0].Claims
	for key, want := range map[string]any{
		"credlease_profile":    "backend-a/dev",
		"credlease_resource":   "https://api.dev.example.com",
		"credlease_purpose":    "process",
		"credlease_project_id": wantProjectID,
	} {
		if got := claims[key]; got != want {
			t.Fatalf("Claims[%s] = %#v, want %#v", key, got, want)
		}
	}
	if claims["credlease_project_id"] == projectRoot {
		t.Fatalf("credlease_project_id leaked raw project root: %q", projectRoot)
	}
	if claims["credlease_session_id"] == "" {
		t.Fatal("credlease_session_id is empty")
	}
}

func TestRunOpenPrintsLaunchURL(t *testing.T) {
	browserClient := &fakeBrowserClient{
		result: browser.OpenResult{
			LaunchURL: "https://admin.dev.example.com/auth/credlease/complete?code=opaque-code",
			ExpiresAt: time.Date(2026, 6, 22, 12, 0, 30, 0, time.UTC),
		},
	}
	app := cli.New(cli.Options{
		Paths:    testPaths(t),
		Profiles: fakeCLIProfiles(),
		Browser:  browserClient,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"open", "admin-web/dev", "--browser", "chrome", "--print-url"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if got, want := stdout.String(), "https://admin.dev.example.com/auth/credlease/complete?code=opaque-code\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if browserClient.request.Profile.Name != "admin-web/dev" {
		t.Fatalf("request profile = %q", browserClient.request.Profile.Name)
	}
	if browserClient.request.Browser != "chrome" {
		t.Fatalf("request browser = %q, want chrome", browserClient.request.Browser)
	}
	if !browserClient.request.PrintURL {
		t.Fatal("request PrintURL = false, want true")
	}
}

func TestRunOpenRejectsUnapprovedProjectBindingBeforeExchange(t *testing.T) {
	approvedRoot := filepath.Join(t.TempDir(), "approved")
	binding, err := projectbinding.Approve(profile.ProjectBindingPathHash, projectbinding.Identity{Root: approvedRoot})
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	profiles := fakeCLIProfiles()
	p := profiles["admin-web/dev"]
	p.ProjectBinding = binding
	profiles["admin-web/dev"] = p
	browserClient := &fakeBrowserClient{
		result: browser.OpenResult{
			LaunchURL: "https://admin.dev.example.com/auth/credlease/complete?code=opaque-code",
			ExpiresAt: time.Date(2026, 6, 22, 12, 0, 30, 0, time.UTC),
		},
	}
	app := cli.New(cli.Options{
		ProjectStartDir: filepath.Join(t.TempDir(), "other"),
		Profiles:        profiles,
		Browser:         browserClient,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"open", "admin-web/dev", "--print-url"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), string(clerr.ProjectNotTrusted)) {
		t.Fatalf("stderr = %q, want project binding error", stderr.String())
	}
	if browserClient.calls != 0 {
		t.Fatalf("browser calls = %d, want 0", browserClient.calls)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRunProfileAddProcessCallsManagerWithPolicy(t *testing.T) {
	manager := &fakeProfileManager{}
	projectRoot := writeGitProject(t, "git@example.com:team/backend-a.git")
	app := cli.New(cli.Options{
		Paths:           testPaths(t),
		ProjectStartDir: projectRoot,
		ProfileManager:  manager,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"profile", "add", "process", "backend-a/dev",
		"--resource", "https://api.dev.example.com",
		"--scope", "repository:read",
		"--scope", "issue:read",
		"--ttl", "10m",
		"--max-ttl", "30m",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want both empty", stdout.String(), stderr.String())
	}
	got := manager.process
	if got.Name != "backend-a/dev" {
		t.Fatalf("Name = %q", got.Name)
	}
	if got.Resource != "https://api.dev.example.com" {
		t.Fatalf("Resource = %q", got.Resource)
	}
	if strings.Join(got.Scopes, ",") != "repository:read,issue:read" {
		t.Fatalf("Scopes = %#v", got.Scopes)
	}
	if got.TokenTTL != 10*time.Minute || got.MaxTokenTTL != 30*time.Minute {
		t.Fatalf("TTLs = %s/%s, want 10m/30m", got.TokenTTL, got.MaxTokenTTL)
	}
	if got.ProjectBinding.Mode != profile.ProjectBindingGitRemoteAndRoot {
		t.Fatalf("ProjectBinding.Mode = %q, want git-remote-and-root", got.ProjectBinding.Mode)
	}
	if got.ProjectBinding.GitRoot != projectRoot {
		t.Fatalf("ProjectBinding.GitRoot = %q, want %q", got.ProjectBinding.GitRoot, projectRoot)
	}
	if got.ProjectBinding.GitRemote != "git@example.com:team/backend-a.git" {
		t.Fatalf("ProjectBinding.GitRemote = %q", got.ProjectBinding.GitRemote)
	}
}

func TestRunProfileAddProcessRejectsUnconfirmedProjectBinding(t *testing.T) {
	manager := &fakeProfileManager{}
	projectRoot := writeGitProject(t, "git@example.com:team/backend-a.git")
	confirmer := &fakeProjectBindingConfirmer{
		err: clerr.New(clerr.ProjectNotTrusted, "project binding approval required"),
	}
	app := cli.New(cli.Options{
		ProjectStartDir:         projectRoot,
		ProfileManager:          manager,
		ProjectBindingConfirmer: confirmer,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"profile", "add", "process", "backend-a/dev",
		"--resource", "https://api.dev.example.com",
		"--scope", "repository:read",
		"--ttl", "10m",
		"--max-ttl", "30m",
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), string(clerr.ProjectNotTrusted)) {
		t.Fatalf("stderr = %q, want project not trusted", stderr.String())
	}
	if manager.process.Name != "" {
		t.Fatalf("manager process request = %#v, want no call", manager.process)
	}
	if confirmer.request.Mode != profile.ProjectBindingGitRemoteAndRoot {
		t.Fatalf("confirm mode = %q, want git-remote-and-root", confirmer.request.Mode)
	}
	if confirmer.request.Identity.Root != projectRoot || confirmer.request.Identity.GitRemote != "git@example.com:team/backend-a.git" {
		t.Fatalf("confirm identity = %#v, want detected project", confirmer.request.Identity)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRunProfileAddProcessUsesConfirmedProjectBinding(t *testing.T) {
	manager := &fakeProfileManager{}
	projectRoot := writeGitProject(t, "git@example.com:team/backend-a.git")
	confirmer := &fakeProjectBindingConfirmer{}
	app := cli.New(cli.Options{
		ProjectStartDir:         projectRoot,
		ProfileManager:          manager,
		ProjectBindingConfirmer: confirmer,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"profile", "add", "process", "backend-a/dev",
		"--resource", "https://api.dev.example.com",
		"--scope", "repository:read",
		"--ttl", "10m",
		"--max-ttl", "30m",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if manager.process.ProjectBinding.GitRoot != projectRoot {
		t.Fatalf("binding root = %q, want %q", manager.process.ProjectBinding.GitRoot, projectRoot)
	}
	if confirmer.request.Identity.GitRemote != "git@example.com:team/backend-a.git" {
		t.Fatalf("confirm remote = %q, want detected remote", confirmer.request.Identity.GitRemote)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want both empty", stdout.String(), stderr.String())
	}
}

func TestRunProfileAddBrowserSessionCallsManagerWithPolicy(t *testing.T) {
	manager := &fakeProfileManager{}
	projectRoot := writeGitProject(t, "git@example.com:team/admin-web.git")
	app := cli.New(cli.Options{
		Paths:           testPaths(t),
		ProjectStartDir: projectRoot,
		ProfileManager:  manager,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"profile", "add", "browser-session", "admin-web/dev",
		"--resource", "https://admin.dev.example.com",
		"--exchange-url", "https://admin.dev.example.com/auth/credlease/browser-sessions",
		"--complete-url", "https://admin.dev.example.com/auth/credlease/complete",
		"--post-login-url", "https://admin.dev.example.com/",
		"--scope", "browser:session:create",
		"--bootstrap-ttl", "60s",
		"--code-ttl", "30s",
		"--session-ttl", "30m",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want both empty", stdout.String(), stderr.String())
	}
	got := manager.browserSession
	if got.Name != "admin-web/dev" {
		t.Fatalf("Name = %q", got.Name)
	}
	if got.Resource != "https://admin.dev.example.com" {
		t.Fatalf("Resource = %q", got.Resource)
	}
	if strings.Join(got.Scopes, ",") != "browser:session:create" {
		t.Fatalf("Scopes = %#v", got.Scopes)
	}
	if got.BootstrapTokenTTL != time.Minute || got.LoginCodeTTL != 30*time.Second || got.WebSessionTTL != 30*time.Minute {
		t.Fatalf("TTLs = %s/%s/%s, want 60s/30s/30m", got.BootstrapTokenTTL, got.LoginCodeTTL, got.WebSessionTTL)
	}
	if got.ExchangeURL != "https://admin.dev.example.com/auth/credlease/browser-sessions" {
		t.Fatalf("ExchangeURL = %q", got.ExchangeURL)
	}
	if got.CompleteURL != "https://admin.dev.example.com/auth/credlease/complete" {
		t.Fatalf("CompleteURL = %q", got.CompleteURL)
	}
	if got.PostLoginURL != "https://admin.dev.example.com/" {
		t.Fatalf("PostLoginURL = %q", got.PostLoginURL)
	}
	if strings.Join(got.AllowedHosts, ",") != "admin.dev.example.com" {
		t.Fatalf("AllowedHosts = %#v, want resource host", got.AllowedHosts)
	}
	if got.ProjectBinding.Mode != profile.ProjectBindingGitRemoteAndRoot {
		t.Fatalf("ProjectBinding.Mode = %q, want git-remote-and-root", got.ProjectBinding.Mode)
	}
	if got.ProjectBinding.GitRoot != projectRoot {
		t.Fatalf("ProjectBinding.GitRoot = %q, want %q", got.ProjectBinding.GitRoot, projectRoot)
	}
	if got.ProjectBinding.GitRemote != "git@example.com:team/admin-web.git" {
		t.Fatalf("ProjectBinding.GitRemote = %q", got.ProjectBinding.GitRemote)
	}
}

func TestRunResetDryRunPrintsPlan(t *testing.T) {
	resetter := &fakeResetter{
		result: resetpkg.Result{
			Files:       []string{"/tmp/credlease/config.yaml", "/tmp/credlease/credlease.sqlite"},
			KeyringKeys: []string{"credlease/talos/hmac/current", "credlease/profile/backend-a/dev/parent-key"},
		},
	}
	app := cli.New(cli.Options{
		Paths:    testPaths(t),
		Resetter: resetter,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"reset", "--dry-run"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if !resetter.options.DryRun {
		t.Fatal("DryRun = false, want true")
	}
	for _, want := range []string{
		"/tmp/credlease/config.yaml",
		"credlease/talos/hmac/current",
		"credlease/profile/backend-a/dev/parent-key",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
	if strings.Contains(stdout.String(), "secret-canary") || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want no secret and empty stderr", stdout.String(), stderr.String())
	}
}

func TestRunResetRequiresExplicitConfirmation(t *testing.T) {
	resetter := &fakeResetter{}
	app := cli.New(cli.Options{
		Paths:    testPaths(t),
		Resetter: resetter,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"reset"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("Run() code = %d, want 2", code)
	}
	if resetter.calls != 0 {
		t.Fatalf("resetter calls = %d, want 0", resetter.calls)
	}
	if !strings.Contains(stderr.String(), "--yes") {
		t.Fatalf("stderr = %q, want --yes guidance", stderr.String())
	}
}

func TestRunResetExecutesWhenConfirmed(t *testing.T) {
	resetter := &fakeResetter{}
	app := cli.New(cli.Options{
		Paths:    testPaths(t),
		Resetter: resetter,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"reset", "--yes"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if resetter.calls != 1 {
		t.Fatalf("resetter calls = %d, want 1", resetter.calls)
	}
	if resetter.options.DryRun {
		t.Fatal("DryRun = true, want false")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want both empty", stdout.String(), stderr.String())
	}
}

func TestRunDoctorPrintsChecksWithoutLeakingSecrets(t *testing.T) {
	checker := &fakeDoctor{
		result: doctor.Result{
			Checks: []doctor.Check{
				{Name: "config", Status: doctor.StatusOK, Message: "config loaded"},
				{Name: "keyring", Status: doctor.StatusOK, Message: "required entries present"},
				{Name: "jwks", Status: doctor.StatusOK, Message: "public keys present"},
			},
		},
	}
	app := cli.New(cli.Options{
		Paths:  testPaths(t),
		Doctor: checker,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"doctor"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if checker.calls != 1 {
		t.Fatalf("doctor calls = %d, want 1", checker.calls)
	}
	for _, want := range []string{"ok config: config loaded", "ok keyring: required entries present"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
	if strings.Contains(stdout.String(), "secret-canary") || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want no secret and empty stderr", stdout.String(), stderr.String())
	}
}

func TestRunDoctorReturnsNonZeroForErrorCheck(t *testing.T) {
	checker := &fakeDoctor{
		result: doctor.Result{
			Checks: []doctor.Check{
				{Name: "keyring", Status: doctor.StatusError, Code: clerr.KeyringUnavailable, Message: "required entry unavailable"},
			},
		},
	}
	app := cli.New(cli.Options{
		Paths:  testPaths(t),
		Doctor: checker,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"doctor"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), string(clerr.KeyringUnavailable)) {
		t.Fatalf("stdout = %q, want keyring error code", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunDoctorRepairCallsRepairWithoutLeakingSecrets(t *testing.T) {
	checker := &fakeDoctor{
		repairResult: doctor.Result{
			Checks: []doctor.Check{
				{Name: "repair-runtime-lock", Status: doctor.StatusOK, Message: "removed stale runtime lock"},
				{Name: "repair-temp-files", Status: doctor.StatusOK, Message: "removed 1 stale temporary file"},
				{Name: "keyring", Status: doctor.StatusOK, Message: "required entries present"},
			},
		},
	}
	app := cli.New(cli.Options{
		Paths:  testPaths(t),
		Doctor: checker,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"doctor", "--repair"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if checker.calls != 0 {
		t.Fatalf("doctor check calls = %d, want 0", checker.calls)
	}
	if checker.repairCalls != 1 {
		t.Fatalf("doctor repair calls = %d, want 1", checker.repairCalls)
	}
	for _, want := range []string{"ok repair-runtime-lock", "ok repair-temp-files", "ok keyring"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
	if strings.Contains(stdout.String(), "secret-canary") || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want no secret and empty stderr", stdout.String(), stderr.String())
	}
}

func TestRunJWKSShowWritesStableJWKSFile(t *testing.T) {
	paths := testPaths(t)
	writeJWKS(t, paths, `{"keys":[{"kty":"RSA","kid":"test","use":"sig"}]}`)
	app := cli.New(cli.Options{Paths: paths})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"jwks", "show"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if got, want := stdout.String(), "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"test\",\"use\":\"sig\"}]}\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunJWKSExportCopiesStableJWKSFile(t *testing.T) {
	paths := testPaths(t)
	body := `{"keys":[{"kty":"RSA","kid":"test","use":"sig"}]}`
	writeJWKS(t, paths, body)
	output := filepath.Join(t.TempDir(), "backend", "credlease-jwks.json")
	app := cli.New(cli.Options{Paths: paths})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"jwks", "export", "--output", output}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != body {
		t.Fatalf("exported jwks = %q, want %q", got, body)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644", info.Mode().Perm())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want both empty", stdout.String(), stderr.String())
	}
}

func TestRunIssuerShowWritesLocalIssuerID(t *testing.T) {
	paths := testPaths(t)
	if err := paths.Ensure(); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	if err := config.Save(paths.ConfigFile, config.File{
		Version: 1,
		Installation: config.Installation{
			ID: "01JTESTINSTALL",
		},
		Runtime: config.Runtime{
			Talos: config.TalosRuntime{
				Mode:      "managed",
				Version:   "test-talos",
				Lifecycle: "on-demand",
			},
		},
		Defaults: config.Defaults{
			TokenTTL:    config.Duration(10 * time.Minute),
			MaxTokenTTL: config.Duration(time.Hour),
		},
		Profiles: map[string]config.Profile{},
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	app := cli.New(cli.Options{Paths: paths})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"issuer", "show"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if got, want := stdout.String(), "credlease-local:01JTESTINSTALL\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func testPaths(t *testing.T) config.Paths {
	t.Helper()
	root := t.TempDir()
	return config.Paths{
		ConfigDir:  filepath.Join(root, "config"),
		ConfigFile: filepath.Join(root, "config", "config.yaml"),
		DataDir:    filepath.Join(root, "data"),
		CacheDir:   filepath.Join(root, "cache"),
	}
}

func writeJWKS(t *testing.T, paths config.Paths, body string) {
	t.Helper()
	if err := os.MkdirAll(paths.DataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(paths.DataDir, "credlease-jwks.json"), []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func writeGitProject(t *testing.T, remote string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatalf("MkdirAll(.git) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "config"), []byte("[remote \"origin\"]\n\turl = "+remote+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(.git/config) error = %v", err)
	}
	return root
}

type fakeCLIProfileResolver map[string]profile.Profile

func (r fakeCLIProfileResolver) Profile(name string) (profile.Profile, error) {
	p, ok := r[name]
	if !ok {
		return profile.Profile{}, clerr.New(clerr.ProfileNotFound, name)
	}
	return p, nil
}

type fakeInitializer struct {
	result bootstrap.Result
	err    error
	calls  int
}

func (i *fakeInitializer) Init(context.Context) (bootstrap.Result, error) {
	i.calls++
	return i.result, i.err
}

type fakeTokenIssuer struct {
	grants     []issuer.Grant
	credential issuer.Credential
}

func (f *fakeTokenIssuer) Issue(_ context.Context, grant issuer.Grant) (issuer.Credential, error) {
	f.grants = append(f.grants, grant)
	if f.credential.AccessToken != "" {
		return f.credential, nil
	}
	return issuer.Credential{
		AccessToken: "jwt-for-" + grant.Profile,
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(grant.TTL),
		Scopes:      append([]string(nil), grant.Scopes...),
	}, nil
}

type fakeChildRunner struct {
	code  int
	input process.RunInput
}

func (r *fakeChildRunner) Run(_ context.Context, input process.RunInput) (int, error) {
	r.input = input
	return r.code, nil
}

type fakeBrowserClient struct {
	request browser.OpenRequest
	result  browser.OpenResult
	calls   int
}

func (c *fakeBrowserClient) Open(_ context.Context, request browser.OpenRequest) (browser.OpenResult, error) {
	c.calls++
	c.request = request
	return c.result, nil
}

type fakeProfileManager struct {
	process        profilemgr.ProcessRequest
	browserSession profilemgr.BrowserSessionRequest
}

func (m *fakeProfileManager) AddProcess(_ context.Context, request profilemgr.ProcessRequest) (profile.Profile, error) {
	m.process = request
	return profile.Profile{Name: request.Name, Kind: profile.KindProcess}, nil
}

func (m *fakeProfileManager) AddBrowserSession(_ context.Context, request profilemgr.BrowserSessionRequest) (profile.Profile, error) {
	m.browserSession = request
	return profile.Profile{Name: request.Name, Kind: profile.KindBrowserSession}, nil
}

type fakeProjectBindingConfirmer struct {
	request cli.ProjectBindingConfirmation
	err     error
}

func (c *fakeProjectBindingConfirmer) ConfirmProjectBinding(_ context.Context, request cli.ProjectBindingConfirmation) error {
	c.request = request
	return c.err
}

type fakeResetter struct {
	result  resetpkg.Result
	options resetpkg.Options
	calls   int
	err     error
}

func (r *fakeResetter) Reset(_ context.Context, options resetpkg.Options) (resetpkg.Result, error) {
	r.calls++
	r.options = options
	return r.result, r.err
}

type fakeDoctor struct {
	result       doctor.Result
	repairResult doctor.Result
	calls        int
	repairCalls  int
	err          error
	repairErr    error
}

func (d *fakeDoctor) Check(context.Context) (doctor.Result, error) {
	d.calls++
	return d.result, d.err
}

func (d *fakeDoctor) Repair(context.Context) (doctor.Result, error) {
	d.repairCalls++
	return d.repairResult, d.repairErr
}

func fakeCLIProfiles() fakeCLIProfileResolver {
	return fakeCLIProfileResolver{
		"backend-a/dev": {
			Name:        "backend-a/dev",
			Kind:        profile.KindProcess,
			Resource:    "https://api.dev.example.com",
			Scopes:      []string{"repository:read"},
			TokenTTL:    10 * time.Minute,
			MaxTokenTTL: 30 * time.Minute,
		},
		"admin-web/dev": {
			Name:              "admin-web/dev",
			Kind:              profile.KindBrowserSession,
			Resource:          "https://admin.dev.example.com",
			Scopes:            []string{"browser:session:create"},
			BootstrapTokenTTL: 60 * time.Second,
			LoginCodeTTL:      30 * time.Second,
			WebSessionTTL:     30 * time.Minute,
			ExchangeURL:       "https://admin.dev.example.com/auth/credlease/browser-sessions",
			CompleteURL:       "https://admin.dev.example.com/auth/credlease/complete",
			PostLoginURL:      "https://admin.dev.example.com/",
			AllowedHosts:      []string{"admin.dev.example.com"},
		},
	}
}

func assertTokenGrant(t *testing.T, grant issuer.Grant) {
	t.Helper()
	if grant.Profile != "backend-a/dev" {
		t.Fatalf("grant profile = %q", grant.Profile)
	}
	if grant.Resource != "https://api.dev.example.com" {
		t.Fatalf("grant resource = %q", grant.Resource)
	}
	if got, want := strings.Join(grant.Scopes, ","), "repository:read"; got != want {
		t.Fatalf("grant scopes = %q, want %q", got, want)
	}
	if grant.TTL != 10*time.Minute {
		t.Fatalf("grant ttl = %s, want 10m", grant.TTL)
	}
	if grant.Claims["credlease_purpose"] != "process" {
		t.Fatalf("grant purpose = %#v, want process", grant.Claims["credlease_purpose"])
	}
}
