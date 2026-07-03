package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/admin"
	"github.com/trknhr/envvault/internal/bootstrap"
	"github.com/trknhr/envvault/internal/browser"
	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/cli"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/doctor"
	"github.com/trknhr/envvault/internal/issuer"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/process"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/profilemgr"
	"github.com/trknhr/envvault/internal/projectbinding"
	resetpkg "github.com/trknhr/envvault/internal/reset"
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

func TestRunHelpWritesUsageWithoutServices(t *testing.T) {
	app := cli.New(cli.Options{})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"--help"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	for _, want := range []string{
		"Usage:",
		"envvault version",
		"envvault credential list",
		"envvault proxy list",
		"envvault exec --env KEY=envvault://<credential> -- <command>",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunVersionWritesVersionWithoutServices(t *testing.T) {
	app := cli.New(cli.Options{})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"version"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "envvault dev" {
		t.Fatalf("stdout = %q, want envvault dev", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunVersionFlagWritesVersionWithoutServices(t *testing.T) {
	app := cli.New(cli.Options{})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"--version"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "envvault dev" {
		t.Fatalf("stdout = %q, want envvault dev", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunVersionRejectsExtraArgs(t *testing.T) {
	app := cli.New(cli.Options{})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"version", "extra"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("Run() code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "usage: envvault version") {
		t.Fatalf("stderr = %q, want usage", stderr.String())
	}
}

func TestRunExecHelpShowsInlineEnvWithoutServices(t *testing.T) {
	app := cli.New(cli.Options{})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"exec", "--help"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	for _, want := range []string{
		"Usage:",
		"envvault exec --env-file .env -- <command>",
		"envvault exec --env OPENAI_API_KEY=envvault://openai/dev",
		"envvault exec --env OPENAI_BASE_URL=envvault://openai/dev/base-url",
		"--env KEY=VALUE",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
	if strings.Contains(stderr.String(), "not implemented") {
		t.Fatalf("stderr = %q, did not expect not implemented", stderr.String())
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
		"# bash completion for envvault",
		"complete -F _envvault envvault",
		"init reset doctor secret credential proxy list admin token exec open jwks issuer completion version",
		"--repair",
		"secret",
		"credential",
		"proxy",
		"proxies",
		"list",
		"admin",
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
			for _, want := range []string{"envvault", "doctor", "secret", "credential", "proxy", "list", "admin", "completion", "version"} {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("stdout = %q, want %q", stdout.String(), want)
				}
			}
			if strings.Contains(stdout.String(), "inject") || strings.Contains(stdout.String(), "profile:") {
				t.Fatalf("stdout = %q, did not expect inject/profile completion", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}
		})
	}
}

func TestRunAdminServeStartsAdminServer(t *testing.T) {
	adminServer := &fakeAdminServer{}
	app := cli.New(cli.Options{
		AdminServer: adminServer,
		AdminTokenSource: func() (string, error) {
			return "generated-token", nil
		},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"admin", "serve", "--addr", "127.0.0.1:0"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if adminServer.calls != 1 {
		t.Fatalf("admin server calls = %d, want 1", adminServer.calls)
	}
	if adminServer.request.Addr != "127.0.0.1:0" {
		t.Fatalf("addr = %q, want 127.0.0.1:0", adminServer.request.Addr)
	}
	if adminServer.request.Token != "generated-token" {
		t.Fatalf("token = %q, want generated-token", adminServer.request.Token)
	}
	if adminServer.request.Stdout != &stdout {
		t.Fatal("stdout writer was not passed to admin server")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunAdminServeAcceptsExplicitToken(t *testing.T) {
	adminServer := &fakeAdminServer{}
	app := cli.New(cli.Options{
		AdminServer: adminServer,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"admin", "serve", "--token", "admin-token"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if adminServer.request.Addr != "127.0.0.1:17890" {
		t.Fatalf("addr = %q, want default admin addr", adminServer.request.Addr)
	}
	if adminServer.request.Token != "admin-token" {
		t.Fatalf("token = %q, want explicit token", adminServer.request.Token)
	}
}

func TestRunAdminServeAcceptsTokenEnv(t *testing.T) {
	t.Setenv("ENVVAULT_ADMIN_TOKEN", "env-admin-token")
	adminServer := &fakeAdminServer{}
	app := cli.New(cli.Options{
		AdminServer: adminServer,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"admin", "serve", "--token-env", "ENVVAULT_ADMIN_TOKEN"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if adminServer.request.Token != "env-admin-token" {
		t.Fatalf("token = %q, want env-admin-token", adminServer.request.Token)
	}
}

func TestRunAdminStartStatusAndStopUseController(t *testing.T) {
	controller := &fakeAdminController{
		startState: admin.State{PID: 12345, URL: "http://127.0.0.1:17890/?token=admin-token"},
		status:     admin.Status{Running: true, State: admin.State{PID: 12345, URL: "http://127.0.0.1:17890/?token=admin-token"}},
		stopState:  admin.State{PID: 12345, URL: "http://127.0.0.1:17890/?token=admin-token"},
	}
	app := cli.New(cli.Options{
		AdminController: controller,
	})

	var stdout, stderr bytes.Buffer
	code := app.Run(context.Background(), []string{"admin", "start"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("start code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if controller.startCalls != 1 {
		t.Fatalf("start calls = %d, want 1", controller.startCalls)
	}
	if !strings.Contains(stdout.String(), "http://127.0.0.1:17890/?token=admin-token") {
		t.Fatalf("start stdout = %q, want admin URL", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = app.Run(context.Background(), []string{"admin", "status"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("status code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "running") || !strings.Contains(stdout.String(), "12345") {
		t.Fatalf("status stdout = %q, want running pid", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = app.Run(context.Background(), []string{"admin", "stop"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("stop code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if controller.stopCalls != 1 {
		t.Fatalf("stop calls = %d, want 1", controller.stopCalls)
	}
	if !strings.Contains(stdout.String(), "stopped") {
		t.Fatalf("stop stdout = %q, want stopped", stdout.String())
	}
}

func TestRunCompletionRejectsUnknownShell(t *testing.T) {
	app := cli.New(cli.Options{})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"completion", "tcsh"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("Run() code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage: envvault completion <bash|zsh|fish|powershell>") {
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
		SQLitePath: filepath.Join(paths.DataDir, "envvault.sqlite"),
		JWKSPath:   filepath.Join(paths.DataDir, "envvault-jwks.json"),
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
	if !strings.Contains(stderr.String(), "ENVVAULT_KEYRING_UNAVAILABLE") {
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
		"--env", "TOKEN=envvault://backend-a/dev?scope=admin",
		"--", "inspect-child",
	}, new(bytes.Buffer), &stderr)

	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "ENVVAULT_REFERENCE_INVALID") {
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
		"--env=TOKEN=envvault://backend-a/dev",
		"--", "inspect-child",
	}, new(bytes.Buffer), &stderr)

	if code != 2 {
		t.Fatalf("Run() code = %d, want 2", code)
	}
	if strings.Contains(stderr.String(), "ENVVAULT_REFERENCE_INVALID") {
		t.Fatalf("stderr = %q, did not expect reference error", stderr.String())
	}
	if !strings.Contains(stderr.String(), "not implemented") {
		t.Fatalf("stderr = %q, want not implemented", stderr.String())
	}
}

func TestRunExecResolvesEnvAndRunsChild(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envFile, []byte("TOKEN=envvault://backend-a/dev\nPLAIN=file-value\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(context.Background(), keyring.CredentialValue("backend-a/dev"), []byte("stored-backend-token")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	runner := &fakeChildRunner{code: 42}
	app := cli.New(cli.Options{
		Paths:     testPaths(t),
		ParentEnv: []string{"TOKEN=raw-parent-secret", "HOME=/tmp/home"},
		Secrets:   secrets,
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
	if got := runner.input.Env["TOKEN"]; got != "stored-backend-token" {
		t.Fatalf("TOKEN = %q, want credential value", got)
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
	if strings.Contains(stderr.String(), "raw-parent-secret") {
		t.Fatalf("stderr leaked parent secret: %q", stderr.String())
	}
}

func TestRunExecResolvesCredentialReferenceFromEnvFile(t *testing.T) {
	root := t.TempDir()
	envFile := filepath.Join(root, ".env")
	if err := os.WriteFile(envFile, []byte("TOKEN=envvault://backend-a/dev\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(context.Background(), keyring.CredentialValue("backend-a/dev"), []byte("stored-backend-token")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	runner := &fakeChildRunner{}
	app := cli.New(cli.Options{
		ProjectStartDir: root,
		Secrets:         secrets,
		Runner:          runner,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"exec", "--env-file", envFile, "--", "child"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if runner.input.Env["TOKEN"] != "stored-backend-token" {
		t.Fatalf("TOKEN = %q, want credential value", runner.input.Env["TOKEN"])
	}
}

func TestRunExecProvidesSignalChannelToRunner(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envFile, []byte("TOKEN=envvault://backend-a/dev\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	runner := &fakeChildRunner{}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(context.Background(), keyring.CredentialValue("backend-a/dev"), []byte("stored-backend-token")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	app := cli.New(cli.Options{
		Secrets: secrets,
		Runner:  runner,
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

func TestRunSecretAddStoresProviderAPIKey(t *testing.T) {
	ctx := context.Background()
	secrets := keyring.NewMemoryStore()
	app := cli.New(cli.Options{
		Secrets: secrets,
		Stdin:   strings.NewReader("sk-test\n"),
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(ctx, []string{
		"secret", "add", "openai/dev",
		"--provider", "openai-compatible",
		"--api-key-stdin",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	got, err := secrets.Get(ctx, keyring.ProviderAPIKey("openai/dev"))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(got) != "sk-test" {
		t.Fatalf("stored api key = %q, want sk-test", got)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want both empty", stdout.String(), stderr.String())
	}
}

func TestRunCredentialAddStoresCredentialValue(t *testing.T) {
	ctx := context.Background()
	paths := testPaths(t)
	secrets := keyring.NewMemoryStore()
	app := cli.New(cli.Options{
		Paths:   paths,
		Secrets: secrets,
		Stdin:   strings.NewReader("postgres://user:pass@localhost/db\n"),
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(ctx, []string{
		"credential", "add", "database/dev",
		"--value-stdin",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	got, err := secrets.Get(ctx, keyring.CredentialValue("database/dev"))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(got) != "postgres://user:pass@localhost/db" {
		t.Fatalf("stored credential = %q", got)
	}
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if strings.Join(cfg.Credentials, ",") != "database/dev" {
		t.Fatalf("Credentials = %#v", cfg.Credentials)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want both empty", stdout.String(), stderr.String())
	}
}

func TestRunCredentialListPrintsNamesWithoutValues(t *testing.T) {
	paths := testPaths(t)
	writeBaseConfig(t, paths)
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cfg.AddCredential("zeta/dev")
	cfg.AddCredential("openai/dev")
	if err := config.Save(paths.ConfigFile, cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	app := cli.New(cli.Options{
		Paths: paths,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"credential", "list"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	for _, want := range []string{"NAME", "openai/dev", "zeta/dev"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
	if strings.Contains(stdout.String(), "sk-secret") || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want no secret and empty stderr", stdout.String(), stderr.String())
	}
}

func TestRunProxyAddStoresProviderProxyProfile(t *testing.T) {
	paths := testPaths(t)
	writeBaseConfig(t, paths)
	app := cli.New(cli.Options{
		Paths: paths,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"proxy", "add", "openai/dev",
		"--provider", "openai-compatible",
		"--target", "https://api.openai.com/v1",
		"--allow-path", "/chat/completions",
		"--allow-method", "POST",
		"--token-ttl", "5m",
		"--project-binding", "none",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	got, err := cfg.Profile("openai/dev")
	if err != nil {
		t.Fatalf("Profile() error = %v", err)
	}
	if got.Kind != profile.KindProviderProxy {
		t.Fatalf("Kind = %q, want provider-proxy", got.Kind)
	}
	if got.CredentialName != "openai/dev" {
		t.Fatalf("CredentialName = %q, want openai/dev", got.CredentialName)
	}
	if got.AuthMode != "bearer" {
		t.Fatalf("AuthMode = %q, want bearer", got.AuthMode)
	}
	if got.Provider != "openai-compatible" || got.TargetURL != "https://api.openai.com/v1" {
		t.Fatalf("provider/target = %q/%q", got.Provider, got.TargetURL)
	}
	if strings.Join(got.AllowedPaths, ",") != "/chat/completions" {
		t.Fatalf("AllowedPaths = %#v", got.AllowedPaths)
	}
	if strings.Join(got.AllowedMethods, ",") != "POST" {
		t.Fatalf("AllowedMethods = %#v", got.AllowedMethods)
	}
	if got.LocalTokenTTL != 5*time.Minute {
		t.Fatalf("LocalTokenTTL = %s, want 5m", got.LocalTokenTTL)
	}
	if got.ProjectBinding.Mode != profile.ProjectBindingNone {
		t.Fatalf("ProjectBinding.Mode = %q, want none", got.ProjectBinding.Mode)
	}
	wantSnippet := strings.Join([]string{
		"Add this to your .env:",
		"ENVVAULT_PROXY_URL=envvault://openai/dev/base-url",
		"ENVVAULT_PROXY_TOKEN=envvault://openai/dev/token",
		"",
	}, "\n")
	if stdout.String() != wantSnippet || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want proxy dotenv snippet on stdout", stdout.String(), stderr.String())
	}
}

func TestRunProxyAddCreatesConfigWhenMissing(t *testing.T) {
	paths := testPaths(t)
	app := cli.New(cli.Options{
		Paths: paths,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"proxy", "add", "openai/dev",
		"--provider", "openai-compatible",
		"--target", "https://api.openai.com/v1",
		"--allow-path", "/chat/completions",
		"--allow-method", "POST",
		"--project-binding", "none",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	got, err := cfg.Profile("openai/dev")
	if err != nil {
		t.Fatalf("Profile() error = %v", err)
	}
	if got.Kind != profile.KindProviderProxy || got.CredentialName != "openai/dev" {
		t.Fatalf("profile = %#v", got)
	}
}

func TestRunInjectAddStoresInjectProfile(t *testing.T) {
	paths := testPaths(t)
	writeBaseConfig(t, paths)
	app := cli.New(cli.Options{
		Paths: paths,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"inject", "add", "database/dev",
		"--credential", "database/dev",
		"--project-binding", "none",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	got, err := cfg.Profile("database/dev")
	if err != nil {
		t.Fatalf("Profile() error = %v", err)
	}
	if got.Kind != profile.KindInject {
		t.Fatalf("Kind = %q, want inject", got.Kind)
	}
	if got.CredentialName != "database/dev" {
		t.Fatalf("CredentialName = %q", got.CredentialName)
	}
	if got.ProjectBinding.Mode != profile.ProjectBindingNone {
		t.Fatalf("ProjectBinding.Mode = %q, want none", got.ProjectBinding.Mode)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want both empty", stdout.String(), stderr.String())
	}
}

func TestRunExecRewritesProviderProxyEnvAndForwardsThroughProxy(t *testing.T) {
	ctx := context.Background()
	var providerAuth, providerPath string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerAuth = r.Header.Get("Authorization")
		providerPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()
	paths := testPaths(t)
	writeBaseConfig(t, paths)
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cfg.Profiles["openai/dev"] = config.Profile{
		Kind:           profile.KindProviderProxy,
		CredentialName: "openai-key/dev",
		AuthMode:       "bearer",
		Provider:       "openai-compatible",
		TargetURL:      target.URL + "/v1",
		AllowedPaths:   []string{"/chat/completions"},
		AllowedMethods: []string{http.MethodPost},
		LocalTokenTTL:  config.Duration(10 * time.Minute),
		ProjectBinding: config.ProjectBinding{Mode: profile.ProjectBindingNone},
	}
	if err := config.Save(paths.ConfigFile, cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue("openai-key/dev"), []byte("sk-real")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	runner := childRunnerFunc(func(ctx context.Context, input process.RunInput) (int, error) {
		baseURL := input.Env["OPENAI_BASE_URL"]
		localToken := input.Env["OPENAI_API_KEY"]
		if !strings.HasPrefix(baseURL, "http://127.0.0.1:") {
			t.Fatalf("OPENAI_BASE_URL = %q, want localhost proxy", baseURL)
		}
		if !strings.HasPrefix(localToken, "envvault-local-") {
			t.Fatalf("OPENAI_API_KEY = %q, want local proxy token", localToken)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat/completions", strings.NewReader(`{"messages":[]}`))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Authorization", "Bearer "+localToken)
		resp, err := target.Client().Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("proxy status = %d, want 200; body=%q", resp.StatusCode, body)
		}
		return 17, nil
	})
	app := cli.New(cli.Options{
		Paths:           paths,
		Secrets:         secrets,
		Profiles:        config.ProfileStore{Path: paths.ConfigFile},
		Issuer:          &fakeTokenIssuer{},
		Runner:          runner,
		ProjectStartDir: t.TempDir(),
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(ctx, []string{
		"exec",
		"--env", "OPENAI_BASE_URL=envvault://openai/dev/base-url",
		"--env", "OPENAI_API_KEY=envvault://openai/dev/token",
		"--", "demo-client",
	}, &stdout, &stderr)

	if code != 17 {
		t.Fatalf("Run() code = %d, want child code 17; stderr=%q", code, stderr.String())
	}
	if providerAuth != "Bearer sk-real" {
		t.Fatalf("provider Authorization = %q, want provider bearer", providerAuth)
	}
	if providerPath != "/v1/chat/completions" {
		t.Fatalf("provider path = %q, want /v1/chat/completions", providerPath)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want both empty", stdout.String(), stderr.String())
	}
}

func TestRunExecResolvesCredentialReference(t *testing.T) {
	ctx := context.Background()
	paths := testPaths(t)
	writeBaseConfig(t, paths)
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue("database/dev"), []byte("postgres://user:pass@localhost/db")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	runner := &fakeChildRunner{code: 23}
	app := cli.New(cli.Options{
		Paths:           paths,
		Secrets:         secrets,
		Profiles:        config.ProfileStore{Path: paths.ConfigFile},
		Issuer:          &fakeTokenIssuer{},
		Runner:          runner,
		ProjectStartDir: t.TempDir(),
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(ctx, []string{
		"exec",
		"--env", "DATABASE_URL=envvault://database/dev",
		"--", "demo-client",
	}, &stdout, &stderr)

	if code != 23 {
		t.Fatalf("Run() code = %d, want child code 23; stderr=%q", code, stderr.String())
	}
	if got := runner.input.Env["DATABASE_URL"]; got != "postgres://user:pass@localhost/db" {
		t.Fatalf("DATABASE_URL = %q", got)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want both empty", stdout.String(), stderr.String())
	}
}

func TestRunProxyListPrintsProxyMetadataWithoutCredentialValues(t *testing.T) {
	paths := testPaths(t)
	writeBaseConfig(t, paths)
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cfg.Profiles["openai/dev"] = config.Profile{
		Kind:           profile.KindProviderProxy,
		CredentialName: "openai-key/dev",
		AuthMode:       "bearer",
		Provider:       "generic",
		TargetURL:      "https://api.openai.com/v1",
		AllowedPaths:   []string{"/chat/completions"},
		AllowedMethods: []string{"POST"},
		LocalTokenTTL:  config.Duration(10 * time.Minute),
		ProjectBinding: config.ProjectBinding{Mode: profile.ProjectBindingNone},
	}
	cfg.Profiles["database/dev"] = config.Profile{
		Kind:           profile.KindInject,
		CredentialName: "database-url/dev",
		ProjectBinding: config.ProjectBinding{Mode: profile.ProjectBindingNone},
	}
	if err := config.Save(paths.ConfigFile, cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	app := cli.New(cli.Options{
		Paths: paths,
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"proxy", "list"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	for _, want := range []string{
		"NAME",
		"CREDENTIAL",
		"TARGET",
		"openai/dev",
		"https://api.openai.com/v1",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
	for _, notWant := range []string{"database/dev", "inject", "database-url/dev", "provider-proxy"} {
		if strings.Contains(stdout.String(), notWant) {
			t.Fatalf("stdout = %q, did not expect %q", stdout.String(), notWant)
		}
	}
	if strings.Contains(stdout.String(), "sk-secret") || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want no secret and empty stderr", stdout.String(), stderr.String())
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
		"envvault_profile":    "backend-a/dev",
		"envvault_resource":   "https://api.dev.example.com",
		"envvault_purpose":    "process",
		"envvault_project_id": wantProjectID,
	} {
		if got := claims[key]; got != want {
			t.Fatalf("Claims[%s] = %#v, want %#v", key, got, want)
		}
	}
	if claims["envvault_project_id"] == projectRoot {
		t.Fatalf("envvault_project_id leaked raw project root: %q", projectRoot)
	}
	if claims["envvault_session_id"] == "" {
		t.Fatal("envvault_session_id is empty")
	}
}

func TestRunOpenPrintsLaunchURL(t *testing.T) {
	browserClient := &fakeBrowserClient{
		result: browser.OpenResult{
			LaunchURL: "https://admin.dev.example.com/auth/envvault/complete?code=opaque-code",
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
	if got, want := stdout.String(), "https://admin.dev.example.com/auth/envvault/complete?code=opaque-code\n"; got != want {
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
			LaunchURL: "https://admin.dev.example.com/auth/envvault/complete?code=opaque-code",
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
		"--exchange-url", "https://admin.dev.example.com/auth/envvault/browser-sessions",
		"--complete-url", "https://admin.dev.example.com/auth/envvault/complete",
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
	if got.ExchangeURL != "https://admin.dev.example.com/auth/envvault/browser-sessions" {
		t.Fatalf("ExchangeURL = %q", got.ExchangeURL)
	}
	if got.CompleteURL != "https://admin.dev.example.com/auth/envvault/complete" {
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
			Files:       []string{"/tmp/envvault/config.yaml", "/tmp/envvault/envvault.sqlite"},
			KeyringKeys: []string{"envvault/talos/hmac/current", "envvault/profile/backend-a/dev/parent-key"},
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
		"/tmp/envvault/config.yaml",
		"envvault/talos/hmac/current",
		"envvault/profile/backend-a/dev/parent-key",
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
	output := filepath.Join(t.TempDir(), "backend", "envvault-jwks.json")
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
	if got, want := stdout.String(), "envvault-local:01JTESTINSTALL\n"; got != want {
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
	if err := os.WriteFile(filepath.Join(paths.DataDir, "envvault-jwks.json"), []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func writeBaseConfig(t *testing.T, paths config.Paths) {
	t.Helper()
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

type childRunnerFunc func(context.Context, process.RunInput) (int, error)

func (f childRunnerFunc) Run(ctx context.Context, input process.RunInput) (int, error) {
	return f(ctx, input)
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

type fakeAdminServer struct {
	request admin.ServeRequest
	err     error
	calls   int
}

func (s *fakeAdminServer) Serve(_ context.Context, request admin.ServeRequest) error {
	s.calls++
	s.request = request
	return s.err
}

type fakeAdminController struct {
	startState  admin.State
	status      admin.Status
	stopState   admin.State
	err         error
	startCalls  int
	statusCalls int
	stopCalls   int
}

func (c *fakeAdminController) Start(context.Context, admin.StartRequest) (admin.State, error) {
	c.startCalls++
	return c.startState, c.err
}

func (c *fakeAdminController) Status(context.Context) (admin.Status, error) {
	c.statusCalls++
	return c.status, c.err
}

func (c *fakeAdminController) Stop(context.Context) (admin.State, error) {
	c.stopCalls++
	return c.stopState, c.err
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
			ExchangeURL:       "https://admin.dev.example.com/auth/envvault/browser-sessions",
			CompleteURL:       "https://admin.dev.example.com/auth/envvault/complete",
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
	if grant.Claims["envvault_purpose"] != "process" {
		t.Fatalf("grant purpose = %#v, want process", grant.Claims["envvault_purpose"])
	}
}
