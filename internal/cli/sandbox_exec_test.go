package cli_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/cli"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/sandbox"
	"github.com/trknhr/envvault/internal/sandboxplugin"
	"github.com/trknhr/envvault/internal/sandboxsession"
)

func TestSandboxExecHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := cli.New(cli.Options{}).Run(context.Background(), []string{"sandbox", "exec", "--help"}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "--target") || !strings.Contains(stdout.String(), "--env-file") {
		t.Fatalf("help: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

type sessionRuntime struct {
	prepareErr  error
	projectRoot string
	prepared    bool
	run         func(context.Context, sandboxsession.Prepared, sandboxsession.Command) (int, error)
}

func (r *sessionRuntime) Prepare(_ context.Context, target sandboxsession.Target) (sandboxsession.Prepared, error) {
	r.prepared = true
	if r.prepareErr != nil {
		return sandboxsession.Prepared{}, r.prepareErr
	}
	root, _ := filepath.EvalSymlinks(target.Directory)
	if r.projectRoot != "" {
		root = r.projectRoot
	}
	return sandboxsession.Prepared{ID: strings.Repeat("a", 64), Target: target,
		Project: sandboxplugin.ProjectIdentity{Root: root},
		Gateway: sandbox.GatewayAccess{ListenAddress: "127.0.0.1:0"}}, nil
}

func (r *sessionRuntime) Run(ctx context.Context, prepared sandboxsession.Prepared, command sandboxsession.Command) (int, error) {
	return r.run(ctx, prepared, command)
}

func sessionFixture(t *testing.T, runtime *sessionRuntime, ttl time.Duration) (cli.App, string) {
	t.Helper()
	const canary = "ENVVAULT_SESSION_UPSTREAM_SYNTHETIC_CANARY"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+canary {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(upstream.Close)
	store := keyring.NewMemoryStore()
	if err := store.Put(context.Background(), keyring.CredentialValue("session/key"), []byte(canary)); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	app := cli.New(cli.Options{
		Profiles: fakeCLIProfileResolver{"session/dev": {
			Name: "session/dev", Kind: profile.KindProviderProxy, CredentialName: "session/key",
			AuthMode: "bearer", Provider: "generic", TargetURL: upstream.URL,
			AllowedPaths: []string{"/probe"}, AllowedMethods: []string{"GET"}, LocalTokenTTL: ttl,
			ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
		}}, Secrets: store, ProjectStartDir: directory, ParentEnv: []string{"UNRELATED=not-forwarded"},
		SandboxSessionRuntimes: map[string]sandboxsession.Runtime{"agent-infra": runtime},
	})
	return app, directory
}

func sessionArgs() []string {
	return []string{"sandbox", "exec", "--runtime", "agent-infra", "--target", "trial", "--non-interactive",
		"--env", "APP_URL=envvault://session/dev/base-url", "--env", "APP_TOKEN=envvault://session/dev/token", "--", "probe"}
}

func sessionRequest(environment map[string]string, token, path string) (int, error) {
	req, err := http.NewRequest("GET", environment["APP_URL"]+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := http.Client{Timeout: 200 * time.Millisecond}
	response, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	return response.StatusCode, nil
}

func TestSandboxExecBrokersRevokesAndPreservesExitCode(t *testing.T) {
	var delivered map[string]string
	runtime := &sessionRuntime{run: func(_ context.Context, prepared sandboxsession.Prepared, command sandboxsession.Command) (int, error) {
		if prepared.ID != strings.Repeat("a", 64) || prepared.Target.Reference != "trial" || len(command.Environment) != 2 {
			t.Fatal("wrong session/environment")
		}
		delivered = command.Environment
		if delivered["APP_TOKEN"] == "ENVVAULT_SESSION_UPSTREAM_SYNTHETIC_CANARY" {
			t.Fatal("raw credential delivered")
		}
		for _, check := range []struct {
			token, path string
			status      int
		}{
			{delivered["APP_TOKEN"], "/probe", 200}, {"invalid", "/probe", 401}, {delivered["APP_TOKEN"], "/denied", 403},
		} {
			if status, err := sessionRequest(delivered, check.token, check.path); err != nil || status != check.status {
				t.Fatalf("request: %d %v", status, err)
			}
		}
		fmt.Fprintln(command.Stdout, "probe succeeded")
		return 17, nil
	}}
	app, directory := sessionFixture(t, runtime, time.Minute)
	file := filepath.Join(directory, "sandbox.env")
	if err := os.WriteFile(file, []byte("APP_URL=envvault://session/dev/base-url\nAPP_TOKEN=envvault://session/dev/token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := app.Run(context.Background(), []string{"sandbox", "exec", "--target", "trial", "--non-interactive", "--env-file", file, "--", "probe"}, &stdout, &stderr)
	if code != 17 || stdout.String() != "probe succeeded\n" || stderr.Len() != 0 {
		t.Fatalf("run: %d %q %q", code, stdout.String(), stderr.String())
	}
	if status, err := sessionRequest(delivered, delivered["APP_TOKEN"], "/probe"); err == nil && status == 200 {
		t.Fatal("lease remained usable after command exit")
	}
}

func TestSandboxExecCancelsAndExpires(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		t.Run(fmt.Sprint("expiry=", expiry), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var delivered map[string]string
			runtime := &sessionRuntime{run: func(childCtx context.Context, _ sandboxsession.Prepared, command sandboxsession.Command) (int, error) {
				delivered = command.Environment
				if !expiry {
					cancel()
				}
				select {
				case <-childCtx.Done():
				case <-time.After(4 * time.Second):
					t.Fatal("session was not canceled")
				}
				return 0, nil
			}}
			ttl := time.Minute
			if expiry {
				ttl = time.Second
			}
			app, _ := sessionFixture(t, runtime, ttl)
			var stdout, stderr bytes.Buffer
			if code := app.Run(ctx, sessionArgs(), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "canceled or credential lease expired") {
				t.Fatalf("cancellation: %d %q", code, stderr.String())
			}
			if status, err := sessionRequest(delivered, delivered["APP_TOKEN"], "/probe"); err == nil && status == 200 {
				t.Fatal("canceled session still authorized")
			}
		})
	}
}

func TestSandboxExecFailurePaths(t *testing.T) {
	for _, scenario := range []string{"prepare", "project", "missing-profile", "raw", "runtime", "command-failed"} {
		t.Run(scenario, func(t *testing.T) {
			called := false
			var delivered map[string]string
			runtime := &sessionRuntime{run: func(_ context.Context, _ sandboxsession.Prepared, command sandboxsession.Command) (int, error) {
				called = true
				delivered = command.Environment
				return 1, errors.New("command failed")
			}}
			app, _ := sessionFixture(t, runtime, time.Minute)
			args := sessionArgs()
			switch scenario {
			case "prepare":
				runtime.prepareErr = errors.New("prepare failed")
			case "project":
				runtime.projectRoot = t.TempDir()
			case "missing-profile":
				args[8] = "APP_URL=envvault://missing/dev/base-url"
				args[10] = "APP_TOKEN=envvault://missing/dev/token"
			case "raw":
				args[8] = "APP_URL=synthetic-secret-canary"
			case "runtime":
				args[3] = "unknown"
			}
			var stdout, stderr bytes.Buffer
			if code := app.Run(context.Background(), args, &stdout, &stderr); code != 1 || (called != (scenario == "command-failed")) {
				t.Fatalf("failure: code=%d called=%v stderr=%q", code, called, stderr.String())
			}
			if strings.Contains(stderr.String(), "synthetic-secret-canary") {
				t.Fatal("credential in error")
			}
			if delivered != nil {
				if status, err := sessionRequest(delivered, delivered["APP_TOKEN"], "/probe"); err == nil && status == 200 {
					t.Fatal("failed command retained access")
				}
			}
		})
	}
}
