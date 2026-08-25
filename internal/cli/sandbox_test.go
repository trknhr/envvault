package cli_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/cli"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/projectbinding"
	"github.com/trknhr/envvault/internal/sandbox"
)

func TestRunSandboxRewritesProxyReferencesAndCleansGateway(t *testing.T) {
	ctx := context.Background()
	const upstreamSecret = "ENVVAULT_TEST_SECRET_DO_NOT_LOG_SANDBOX"
	var providerMu sync.Mutex
	var providerAuth, providerPath string
	targetCalls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerMu.Lock()
		targetCalls++
		providerAuth = r.Header.Get("Authorization")
		providerPath = r.URL.Path
		providerMu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "created")
	}))
	defer target.Close()
	profiles := fakeCLIProfileResolver{
		"openai/dev": {
			Name:           "openai/dev",
			Kind:           profile.KindProviderProxy,
			CredentialName: "openai-key/dev",
			AuthMode:       "bearer",
			Provider:       "openai-compatible",
			TargetURL:      target.URL + "/v1",
			AllowedPaths:   []string{"/chat/completions"},
			AllowedMethods: []string{http.MethodPost},
			LocalTokenTTL:  10 * time.Minute,
			ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
		},
	}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue("openai-key/dev"), []byte(upstreamSecret)); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	var gatewayURL string
	var gatewayToken string
	runtime := &fakeSandboxRuntime{exitCode: 19}
	runtime.inspect = func(ctx context.Context, spec sandbox.Spec) error {
		if spec.Image != "fixture:test" || strings.Join(spec.Command, " ") != "run fixture" {
			return errors.New("unexpected image or command")
		}
		if spec.SecurityLevel != connection.SecurityBrokered {
			return errors.New("unexpected security level")
		}
		for _, value := range spec.Environment {
			if strings.Contains(value, upstreamSecret) {
				return errors.New("upstream secret reached sandbox environment")
			}
		}
		gatewayURL = spec.Environment["API_BASE_URL"]
		localToken := spec.Environment["API_TOKEN"]
		gatewayToken = localToken
		if !strings.HasPrefix(gatewayURL, "http://127.0.0.1:") || !strings.HasPrefix(localToken, "envvault-local-") {
			return errors.New("sandbox did not receive proxy capability")
		}
		if spec.Gateway.Network != "tcp" || spec.Gateway.Address == "" {
			return errors.New("sandbox gateway metadata is missing")
		}
		for _, request := range []struct {
			method string
			path   string
			want   int
		}{
			{method: http.MethodGet, path: "/chat/completions", want: http.StatusForbidden},
			{method: http.MethodPost, path: "/not-allowed", want: http.StatusForbidden},
			{method: http.MethodPost, path: "/chat/completions", want: http.StatusCreated},
		} {
			req, err := http.NewRequestWithContext(ctx, request.method, gatewayURL+request.path, nil)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+localToken)
			resp, err := target.Client().Do(req)
			if err != nil {
				return err
			}
			_ = resp.Body.Close()
			if resp.StatusCode != request.want {
				return errors.New("unexpected gateway response")
			}
		}
		return nil
	}
	workspace := t.TempDir()
	app := cli.New(cli.Options{
		ProjectStartDir: workspace,
		Profiles:        profiles,
		Secrets:         secrets,
		SandboxRuntimes: map[string]sandbox.Runtime{"fake": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(ctx, []string{
		"sandbox", "run",
		"--runtime", "fake",
		"--image", "fixture:test",
		"--env", "API_BASE_URL=envvault://openai/dev/base-url",
		"--env", "API_TOKEN=envvault://openai/dev/token",
		"--", "run", "fixture",
	}, &stdout, &stderr)

	combinedOutput := stdout.String() + stderr.String()
	if strings.Contains(combinedOutput, upstreamSecret) || strings.Contains(combinedOutput, "envvault-local-") {
		t.Fatal("CLI output leaked a credential or session capability")
	}
	if code != 19 {
		t.Fatalf("Run() code = %d, want 19", code)
	}
	providerMu.Lock()
	callsOK := targetCalls == 1
	authOK := providerAuth == "Bearer "+upstreamSecret
	pathOK := providerPath == "/v1/chat/completions"
	providerMu.Unlock()
	if !callsOK || !authOK || !pathOK {
		t.Fatalf("provider request mismatch (calls_ok=%t, auth_ok=%t, path_ok=%t)", callsOK, authOK, pathOK)
	}
	if !strings.Contains(stderr.String(), "sandbox: sbx-fake") || !strings.Contains(stderr.String(), "security: brokered") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if strings.Join(runtime.eventsSnapshot(), ",") != "check,create,start,wait,remove" {
		t.Fatalf("runtime events = %#v", runtime.eventsSnapshot())
	}
	client := &http.Client{Timeout: 100 * time.Millisecond}
	req, err := http.NewRequest(http.MethodPost, gatewayURL+"/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest(after cleanup) error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+gatewayToken)
	if response, err := client.Do(req); err == nil {
		_ = response.Body.Close()
		t.Fatal("gateway capability remained usable after sandbox exit")
	}
}

func TestRunSandboxAttachesURLPreservingOutboundProfileAndCleansBroker(t *testing.T) {
	ctx := context.Background()
	const upstreamSecret = "ENVVAULT_OUTBOUND_SECRET_DO_NOT_LOG"
	var providerMu sync.Mutex
	var providerCalls int
	var providerAuth, providerPath string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerMu.Lock()
		providerCalls++
		providerAuth = r.Header.Get("Authorization")
		providerPath = r.URL.Path
		providerMu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer target.Close()
	profiles := fakeCLIProfileResolver{
		"gemini/dev": {
			Name:           "gemini/dev",
			Kind:           profile.KindProviderProxy,
			CredentialName: "gemini-key/dev",
			AuthMode:       "bearer",
			Provider:       "generic",
			TargetURL:      target.URL + "/v1",
			AllowedPaths:   []string{"/models/generateContent"},
			AllowedMethods: []string{http.MethodPost},
			LocalTokenTTL:  10 * time.Minute,
			ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
		},
	}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue("gemini-key/dev"), []byte(upstreamSecret)); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	workspace := t.TempDir()
	envFile := filepath.Join(workspace, ".env")
	if err := os.WriteFile(envFile, []byte("GEMINI_API_KEY=envvault://gemini-key/dev\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(.env) error = %v", err)
	}

	baseRuntime := &fakeSandboxRuntime{}
	var proxyCapabilityURL string
	runtime := &fakeEgressSandboxRuntime{fakeSandboxRuntime: baseRuntime}
	runtime.attach = func(_ context.Context, config connection.EgressClientConfig) (sandbox.EgressAttachment, error) {
		if strings.Contains(config.ProxyURL, upstreamSecret) || strings.Contains(string(config.CACertificatePEM), upstreamSecret) {
			return sandbox.EgressAttachment{}, errors.New("upstream credential reached runtime adapter")
		}
		if len(config.CredentialReferences) != 1 || config.CredentialReferences[0] != "envvault://gemini-key/dev" {
			return sandbox.EgressAttachment{}, errors.New("outbound credential reference is missing")
		}
		proxyCapabilityURL = config.ProxyURL
		return sandbox.EgressAttachment{
			Environment: map[string]string{"HTTP_PROXY": config.ProxyURL},
			Mode:        sandbox.EgressProxyEnvironment,
		}, nil
	}
	baseRuntime.inspect = func(ctx context.Context, spec sandbox.Spec) error {
		if spec.SecurityLevel != connection.SecurityBrokered {
			return errors.New("unexpected security level")
		}
		if spec.Environment["GEMINI_API_KEY"] != "envvault://gemini-key/dev" {
			return errors.New("late-bound credential reference was not preserved")
		}
		for _, value := range spec.Environment {
			if strings.Contains(value, upstreamSecret) {
				return errors.New("upstream credential reached sandbox environment")
			}
		}
		proxyURL, err := url.Parse(spec.Environment["HTTP_PROXY"])
		if err != nil {
			return err
		}
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL+"/v1/models/generateContent", nil)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+spec.Environment["GEMINI_API_KEY"])
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusAccepted {
			return errors.New("URL-preserving provider request failed")
		}
		return nil
	}
	app := cli.New(cli.Options{
		ProjectStartDir: workspace,
		Profiles:        profiles,
		Secrets:         secrets,
		SandboxRuntimes: map[string]sandbox.Runtime{"fake-egress": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(ctx, []string{
		"sandbox", "run", "--runtime", "fake-egress",
		"--outbound-profile", "gemini/dev",
		"--env-file", envFile,
		"--image", "fixture:test", "--", "run", "fixture",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d; stderr=%q", code, stderr.String())
	}
	parsedProxyURL, err := url.Parse(proxyCapabilityURL)
	if err != nil || parsedProxyURL.User == nil {
		t.Fatalf("runtime received invalid proxy URL")
	}
	capability, _ := parsedProxyURL.User.Password()
	combinedOutput := stdout.String() + stderr.String()
	if strings.Contains(combinedOutput, upstreamSecret) || strings.Contains(combinedOutput, capability) || strings.Contains(combinedOutput, proxyCapabilityURL) {
		t.Fatal("CLI output leaked an upstream credential or proxy capability")
	}
	if !strings.Contains(stderr.String(), "outbound: proxy-environment via gemini/dev") {
		t.Fatalf("stderr = %q, want outbound attachment metadata", stderr.String())
	}
	providerMu.Lock()
	gotCalls := providerCalls
	gotAuth := providerAuth
	gotPath := providerPath
	providerMu.Unlock()
	if gotCalls != 1 || gotAuth != "Bearer "+upstreamSecret || gotPath != "/v1/models/generateContent" {
		t.Fatalf("provider request mismatch (calls=%d auth_ok=%t path=%q)", gotCalls, gotAuth == "Bearer "+upstreamSecret, gotPath)
	}
	connection, err := net.DialTimeout("tcp", parsedProxyURL.Host, 100*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		t.Fatal("outbound broker remained reachable after sandbox exit")
	}
}

func TestRunSandboxRejectsCredentialReferenceNotAttachedToOutboundProfile(t *testing.T) {
	ctx := context.Background()
	profiles := fakeCLIProfileResolver{
		"gemini/dev": {
			Name:           "gemini/dev",
			Kind:           profile.KindProviderProxy,
			CredentialName: "gemini-key/dev",
			AuthMode:       "bearer",
			Provider:       "generic",
			TargetURL:      "https://generativelanguage.googleapis.com/v1beta/openai",
			AllowedPaths:   []string{"/chat/completions"},
			AllowedMethods: []string{http.MethodPost},
			LocalTokenTTL:  time.Minute,
			ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
		},
	}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue("gemini-key/dev"), []byte("secret-canary")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	baseRuntime := &fakeSandboxRuntime{}
	runtime := &fakeEgressSandboxRuntime{fakeSandboxRuntime: baseRuntime}
	runtime.attach = func(context.Context, connection.EgressClientConfig) (sandbox.EgressAttachment, error) {
		return sandbox.EgressAttachment{}, errors.New("AttachEgress must not run")
	}
	app := cli.New(cli.Options{
		ProjectStartDir: t.TempDir(),
		Profiles:        profiles,
		Secrets:         secrets,
		SandboxRuntimes: map[string]sandbox.Runtime{"fake-egress": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(ctx, []string{
		"sandbox", "run", "--runtime", "fake-egress",
		"--outbound-profile", "gemini/dev",
		"--env", "GEMINI_API_KEY=envvault://other-key/dev",
		"--image", "fixture:test", "--", "run",
	}, &stdout, &stderr)

	if code != 1 || !strings.Contains(stderr.String(), "matching outbound profile") {
		t.Fatalf("Run() code/stderr = %d/%q", code, stderr.String())
	}
	if strings.Join(baseRuntime.eventsSnapshot(), ",") != "check" {
		t.Fatalf("runtime events = %#v, want preflight check only", baseRuntime.eventsSnapshot())
	}
	if strings.Contains(stdout.String()+stderr.String(), "secret-canary") {
		t.Fatal("output leaked outbound credential")
	}
}

func TestRunSandboxAllAttachesEveryOutboundProfileAllowedForProject(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	workspaceHash, err := projectbinding.PathHash(workspace)
	if err != nil {
		t.Fatalf("PathHash() error = %v", err)
	}
	profiles := fakeCLIProfileResolver{
		"zeta/dev": {
			Name:           "zeta/dev",
			Kind:           profile.KindProviderProxy,
			CredentialName: "zeta-key/dev",
			Provider:       "generic",
			TargetURL:      "https://zeta.example.com/v1",
			AllowedPaths:   []string{"/run"},
			AllowedMethods: []string{http.MethodPost},
			LocalTokenTTL:  time.Minute,
			ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
		},
		"alpha/dev": {
			Name:           "alpha/dev",
			Kind:           profile.KindProviderProxy,
			CredentialName: "alpha-key/dev",
			Provider:       "generic",
			TargetURL:      "https://alpha.example.com/v1",
			AllowedPaths:   []string{"/run"},
			AllowedMethods: []string{http.MethodPost},
			LocalTokenTTL:  time.Minute,
			ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
		},
		"bound/dev": {
			Name:           "bound/dev",
			Kind:           profile.KindProviderProxy,
			CredentialName: "bound-key/dev",
			Provider:       "generic",
			TargetURL:      "https://bound.example.com/v1",
			AllowedPaths:   []string{"/run"},
			AllowedMethods: []string{http.MethodPost},
			LocalTokenTTL:  time.Minute,
			ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingPathHash, PathHash: workspaceHash},
		},
		"other-project/dev": {
			Name:           "other-project/dev",
			Kind:           profile.KindProviderProxy,
			CredentialName: "other-key/dev",
			Provider:       "generic",
			TargetURL:      "https://other.example.com/v1",
			AllowedPaths:   []string{"/run"},
			AllowedMethods: []string{http.MethodPost},
			LocalTokenTTL:  time.Minute,
			ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingPathHash, PathHash: "sha256:not-this-project"},
		},
		"raw/dev": {
			Name:           "raw/dev",
			Kind:           profile.KindInject,
			CredentialName: "raw-key/dev",
			ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
		},
	}
	secrets := keyring.NewMemoryStore()
	for name, value := range map[string]string{
		"alpha-key/dev": "alpha-secret-canary",
		"bound-key/dev": "bound-secret-canary",
		"zeta-key/dev":  "zeta-secret-canary",
	} {
		if err := secrets.Put(ctx, keyring.CredentialValue(name), []byte(value)); err != nil {
			t.Fatalf("Put(%s) error = %v", name, err)
		}
	}
	baseRuntime := &fakeSandboxRuntime{}
	runtime := &fakeEgressSandboxRuntime{fakeSandboxRuntime: baseRuntime}
	runtime.attach = func(_ context.Context, config connection.EgressClientConfig) (sandbox.EgressAttachment, error) {
		want := []string{"envvault://alpha-key/dev", "envvault://bound-key/dev", "envvault://zeta-key/dev"}
		if strings.Join(config.CredentialReferences, ",") != strings.Join(want, ",") {
			return sandbox.EgressAttachment{}, errors.New("--all selected unexpected outbound credential references")
		}
		return sandbox.EgressAttachment{
			Environment: map[string]string{"HTTP_PROXY": config.ProxyURL},
			Mode:        sandbox.EgressProxyEnvironment,
		}, nil
	}
	app := cli.New(cli.Options{
		ProjectStartDir: workspace,
		Profiles:        profiles,
		Secrets:         secrets,
		SandboxRuntimes: map[string]sandbox.Runtime{"fake-egress": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(ctx, []string{
		"sandbox", "run", "--runtime", "fake-egress", "--all",
		"--image", "fixture:test", "--", "run",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "outbound: proxy-environment via alpha/dev, bound/dev, zeta/dev") {
		t.Fatalf("stderr = %q, want stable expanded outbound profile names", stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "secret-canary") {
		t.Fatal("CLI output leaked an outbound credential")
	}
}

func TestRunSandboxAllRejectsExplicitOutboundProfiles(t *testing.T) {
	baseRuntime := &fakeSandboxRuntime{}
	runtime := &fakeEgressSandboxRuntime{fakeSandboxRuntime: baseRuntime}
	app := cli.New(cli.Options{
		ProjectStartDir: t.TempDir(),
		Profiles:        fakeCLIProfileResolver{},
		SandboxRuntimes: map[string]sandbox.Runtime{"fake-egress": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"sandbox", "run", "--runtime", "fake-egress", "--all",
		"--outbound-profile", "gemini/dev",
		"--image", "fixture:test", "--", "run",
	}, &stdout, &stderr)

	if code != 1 || !strings.Contains(stderr.String(), "--all and --outbound-profile cannot be used together") {
		t.Fatalf("Run() code/stderr = %d/%q", code, stderr.String())
	}
	if len(baseRuntime.eventsSnapshot()) != 0 {
		t.Fatalf("runtime events = %#v, want validation before runtime check", baseRuntime.eventsSnapshot())
	}
}

func TestRunSandboxAllRejectsWhenNoOutboundProfilesAreAvailable(t *testing.T) {
	baseRuntime := &fakeSandboxRuntime{}
	runtime := &fakeEgressSandboxRuntime{fakeSandboxRuntime: baseRuntime}
	app := cli.New(cli.Options{
		ProjectStartDir: t.TempDir(),
		Profiles: fakeCLIProfileResolver{
			"raw/dev": {
				Name:           "raw/dev",
				Kind:           profile.KindInject,
				CredentialName: "raw-key/dev",
				ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
			},
		},
		SandboxRuntimes: map[string]sandbox.Runtime{"fake-egress": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"sandbox", "run", "--runtime", "fake-egress", "--all",
		"--image", "fixture:test", "--", "run",
	}, &stdout, &stderr)

	if code != 1 || !strings.Contains(stderr.String(), "no outbound profiles are available for the current project") {
		t.Fatalf("Run() code/stderr = %d/%q", code, stderr.String())
	}
	if strings.Join(baseRuntime.eventsSnapshot(), ",") != "check" {
		t.Fatalf("runtime events = %#v, want preflight check only", baseRuntime.eventsSnapshot())
	}
}

func TestRunSandboxRejectsOutboundProfileForUnsupportedRuntime(t *testing.T) {
	runtime := &fakeSandboxRuntime{}
	app := cli.New(cli.Options{
		ProjectStartDir: t.TempDir(),
		SandboxRuntimes: map[string]sandbox.Runtime{"fake": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"sandbox", "run", "--runtime", "fake",
		"--outbound-profile", "gemini/dev",
		"--image", "fixture:test", "--", "run",
	}, &stdout, &stderr)

	if code != 1 || !strings.Contains(stderr.String(), "does not support outbound profile attachment") {
		t.Fatalf("Run() code/stderr = %d/%q", code, stderr.String())
	}
	if strings.Join(runtime.eventsSnapshot(), ",") != "check" {
		t.Fatalf("runtime events = %#v, want preflight check only", runtime.eventsSnapshot())
	}
}

func TestRunSandboxBypassesItsBaseURLGatewayWhenOutboundProxyIsAttached(t *testing.T) {
	ctx := context.Background()
	profiles := fakeCLIProfileResolver{
		"base/dev": {
			Name:           "base/dev",
			Kind:           profile.KindProviderProxy,
			CredentialName: "base-key/dev",
			Provider:       "generic",
			TargetURL:      "https://api.example.com/v1",
			AllowedPaths:   []string{"/messages"},
			AllowedMethods: []string{http.MethodPost},
			LocalTokenTTL:  time.Minute,
			ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
		},
		"outbound/dev": {
			Name:           "outbound/dev",
			Kind:           profile.KindProviderProxy,
			CredentialName: "outbound-key/dev",
			Provider:       "generic",
			TargetURL:      "https://tools.example.com/v1",
			AllowedPaths:   []string{"/run"},
			AllowedMethods: []string{http.MethodPost},
			LocalTokenTTL:  time.Minute,
			ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
		},
	}
	secrets := keyring.NewMemoryStore()
	for name, value := range map[string]string{"base-key/dev": "base-secret", "outbound-key/dev": "outbound-secret"} {
		if err := secrets.Put(ctx, keyring.CredentialValue(name), []byte(value)); err != nil {
			t.Fatalf("Put(%s) error = %v", name, err)
		}
	}
	baseRuntime := &fakeSandboxRuntime{}
	runtime := &fakeEgressSandboxRuntime{fakeSandboxRuntime: baseRuntime}
	runtime.attach = func(_ context.Context, config connection.EgressClientConfig) (sandbox.EgressAttachment, error) {
		return sandbox.EgressAttachment{
			Environment: map[string]string{"HTTP_PROXY": config.ProxyURL},
			Mode:        sandbox.EgressProxyEnvironment,
		}, nil
	}
	baseRuntime.inspect = func(_ context.Context, spec sandbox.Spec) error {
		baseURL, err := url.Parse(spec.Environment["INTERNAL_BASE_URL"])
		if err != nil || baseURL.Host == "" {
			return errors.New("base URL gateway is missing")
		}
		wantValues := []string{"existing.example", baseURL.Host}
		for _, key := range []string{"NO_PROXY", "no_proxy"} {
			for _, want := range wantValues {
				if !containsCommaValue(spec.Environment[key], want) {
					return errors.New("EnvVault gateway is missing from NO_PROXY")
				}
			}
		}
		return nil
	}
	app := cli.New(cli.Options{
		ProjectStartDir: t.TempDir(),
		Profiles:        profiles,
		Secrets:         secrets,
		SandboxRuntimes: map[string]sandbox.Runtime{"fake-egress": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(ctx, []string{
		"sandbox", "run", "--runtime", "fake-egress",
		"--outbound-profile", "outbound/dev",
		"--env", "NO_PROXY=existing.example",
		"--env", "INTERNAL_BASE_URL=envvault://base/dev/base-url",
		"--env", "INTERNAL_TOKEN=envvault://base/dev/token",
		"--image", "fixture:test", "--", "run",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d; stderr=%q", code, stderr.String())
	}
}

func TestRunSandboxAutomaticallyAttachesCodexAgentAuthWithoutEnvFile(t *testing.T) {
	ctx := context.Background()
	const upstreamSecret = "ENVVAULT_TEST_CODEX_SECRET_DO_NOT_LOG"
	var providerMu sync.Mutex
	var providerAuth, providerPath string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerMu.Lock()
		providerAuth = r.Header.Get("Authorization")
		providerPath = r.URL.Path
		providerMu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"id":"response_test"}`)
	}))
	defer target.Close()

	profiles := fakeCLIProfileResolver{
		"openai-codex/dev": compatibleCodexProfile("openai-codex/dev", "openai-key/dev", target.URL+"/v1"),
	}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue("openai-key/dev"), []byte(upstreamSecret)); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	var gatewayURL, gatewayToken string
	runtime := &fakeSandboxRuntime{}
	runtime.inspect = func(ctx context.Context, spec sandbox.Spec) error {
		if spec.SecurityLevel != connection.SecurityBrokered {
			return errors.New("unexpected security level")
		}
		if got := spec.Environment["ENVVAULT_CODEX_TOKEN"]; !strings.HasPrefix(got, "envvault-local-") {
			return errors.New("Codex did not receive a short-lived capability")
		}
		gatewayToken = spec.Environment["ENVVAULT_CODEX_TOKEN"]
		for _, value := range spec.Environment {
			if strings.Contains(value, upstreamSecret) {
				return errors.New("upstream credential reached sandbox environment")
			}
		}
		for _, argument := range spec.Command {
			if strings.Contains(argument, upstreamSecret) || strings.Contains(argument, gatewayToken) {
				return errors.New("credential or capability reached Codex command arguments")
			}
		}
		if got, ok := commandConfigOverride(spec.Command, "model_provider"); !ok || got != "envvault" {
			return errors.New("Codex model provider override is missing")
		}
		var ok bool
		gatewayURL, ok = commandConfigOverride(spec.Command, "model_providers.envvault.base_url")
		if !ok || !strings.HasPrefix(gatewayURL, "http://127.0.0.1:") {
			return errors.New("Codex gateway base URL override is missing")
		}
		if got, ok := commandConfigOverride(spec.Command, "model_providers.envvault.env_key"); !ok || got != "ENVVAULT_CODEX_TOKEN" {
			return errors.New("Codex token environment override is missing")
		}
		if len(spec.Command) < 2 || strings.Join(spec.Command[len(spec.Command)-2:], " ") != "exec fix" {
			return errors.New("Codex user arguments were not preserved")
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, gatewayURL+"/responses", strings.NewReader(`{"model":"test"}`))
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+gatewayToken)
		response, err := target.Client().Do(request)
		if err != nil {
			return err
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return errors.New("Codex gateway request failed")
		}
		return nil
	}
	app := cli.New(cli.Options{
		ProjectStartDir: t.TempDir(),
		Profiles:        profiles,
		Secrets:         secrets,
		SandboxRuntimes: map[string]sandbox.Runtime{"fake": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(ctx, []string{
		"sandbox", "run", "-it",
		"--runtime", "fake",
		"--image", "envvault-codex:test",
		"--", "codex", "exec", "fix",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d; stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), upstreamSecret) || strings.Contains(stdout.String()+stderr.String(), gatewayToken) {
		t.Fatal("CLI output leaked a credential or capability")
	}
	if !strings.Contains(stderr.String(), "agent-auth: codex via openai-codex/dev") {
		t.Fatalf("stderr = %q, want selected Codex auth profile", stderr.String())
	}
	providerMu.Lock()
	authOK := providerAuth == "Bearer "+upstreamSecret
	pathOK := providerPath == "/v1/responses"
	providerMu.Unlock()
	if !authOK || !pathOK {
		t.Fatalf("provider request mismatch (auth_ok=%t, path_ok=%t)", authOK, pathOK)
	}
	client := &http.Client{Timeout: 100 * time.Millisecond}
	request, err := http.NewRequest(http.MethodPost, gatewayURL+"/responses", nil)
	if err != nil {
		t.Fatalf("NewRequest(after cleanup) error = %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+gatewayToken)
	if response, err := client.Do(request); err == nil {
		_ = response.Body.Close()
		t.Fatal("Codex gateway capability remained usable after sandbox exit")
	}
}

func TestRunSandboxRequiresExplicitCodexProfileWhenDiscoveryIsAmbiguous(t *testing.T) {
	profiles := fakeCLIProfileResolver{
		"openai/personal": compatibleCodexProfile("openai/personal", "openai-personal", "https://api.openai.com/v1"),
		"openai/work":     compatibleCodexProfile("openai/work", "openai-work", "https://api.openai.com/v1"),
	}
	runtime := &fakeSandboxRuntime{}
	app := cli.New(cli.Options{
		ProjectStartDir: t.TempDir(),
		Profiles:        profiles,
		SandboxRuntimes: map[string]sandbox.Runtime{"fake": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"sandbox", "run", "--runtime", "fake", "--image", "fixture:test", "--", "codex",
	}, &stdout, &stderr)

	if code != 1 || !strings.Contains(stderr.String(), "multiple compatible codex agent auth profiles") ||
		!strings.Contains(stderr.String(), "--agent-auth") {
		t.Fatalf("Run() code/stderr = %d/%q", code, stderr.String())
	}
	if len(runtime.eventsSnapshot()) != 0 {
		t.Fatalf("runtime events = %#v, want failure before runtime check", runtime.eventsSnapshot())
	}
}

func TestRunSandboxUsesExplicitCodexAgentAuthProfile(t *testing.T) {
	profiles := fakeCLIProfileResolver{
		"openai/personal": compatibleCodexProfile("openai/personal", "openai-personal", "https://api.openai.com/v1"),
		"openai/work":     compatibleCodexProfile("openai/work", "openai-work", "https://api.openai.com/v1"),
	}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(context.Background(), keyring.CredentialValue("openai-work"), []byte("work-secret-canary")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	runtime := &fakeSandboxRuntime{}
	runtime.inspect = func(_ context.Context, spec sandbox.Spec) error {
		baseURL, ok := commandConfigOverride(spec.Command, "model_providers.envvault.base_url")
		if !ok || !strings.HasSuffix(baseURL, "/openai/work") {
			return errors.New("explicit agent auth profile was not selected")
		}
		if strings.Contains(strings.Join(spec.Command, " "), "work-secret-canary") {
			return errors.New("upstream credential reached command arguments")
		}
		return nil
	}
	app := cli.New(cli.Options{
		ProjectStartDir: t.TempDir(),
		Profiles:        profiles,
		Secrets:         secrets,
		SandboxRuntimes: map[string]sandbox.Runtime{"fake": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"sandbox", "run", "--agent-auth", "openai/work",
		"--runtime", "fake", "--image", "fixture:test", "--", "codex",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "agent-auth: codex via openai/work") {
		t.Fatalf("stderr = %q, want explicit profile", stderr.String())
	}
}

func TestRunSandboxUsesIsolatedCodexNativeAuthState(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	wantSource := filepath.Join(dataDir, "agent-auth", "codex", "work")
	runtime := &fakeSandboxRuntime{}
	runtime.inspect = func(_ context.Context, spec sandbox.Spec) error {
		if spec.SecurityLevel != connection.SecurityMaterializedStatic {
			return errors.New("native auth did not lower the security level")
		}
		if spec.Environment["CODEX_HOME"] != "/home/envvault/.codex" {
			return errors.New("Codex native home was not configured")
		}
		if _, ok := spec.Environment["ENVVAULT_CODEX_TOKEN"]; ok {
			return errors.New("brokered capability was attached to native auth")
		}
		resolvedWant, err := filepath.EvalSymlinks(wantSource)
		if err != nil {
			return err
		}
		if len(spec.Mounts) != 1 || spec.Mounts[0].Source != resolvedWant || spec.Mounts[0].Target != "/home/envvault/.codex" || spec.Mounts[0].ReadOnly {
			return errors.New("isolated writable Codex state was not mounted")
		}
		if got, ok := commandConfigOverride(spec.Command, "cli_auth_credentials_store"); !ok || got != "file" {
			return errors.New("Codex file credential storage was not configured")
		}
		if strings.Join(spec.Command[len(spec.Command)-2:], " ") != "login --device-auth" {
			return errors.New("Codex login arguments were not preserved")
		}
		return os.WriteFile(filepath.Join(spec.Mounts[0].Source, "auth.json"), []byte("refresh-state"), 0o600)
	}
	app := cli.New(cli.Options{
		Paths:           config.Paths{DataDir: dataDir},
		ProjectStartDir: t.TempDir(),
		SandboxRuntimes: map[string]sandbox.Runtime{"fake": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"sandbox", "run", "-it",
		"--agent-auth", "native",
		"--agent-auth-profile", "work",
		"--runtime", "fake", "--image", "fixture:test",
		"--", "codex", "login", "--device-auth",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "agent-auth: codex native (profile work)") ||
		!strings.Contains(stderr.String(), "security: materialized-static") ||
		!strings.Contains(stderr.String(), "warning: raw credentials") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	contents, err := os.ReadFile(filepath.Join(wantSource, "auth.json"))
	if err != nil || string(contents) != "refresh-state" {
		t.Fatalf("persisted auth state = %q/%v", contents, err)
	}
	info, err := os.Stat(wantSource)
	if err != nil {
		t.Fatalf("Stat(native auth state) error = %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("native auth state mode = %v, want 0700", info.Mode().Perm())
	}
}

func TestRunSandboxRejectsInvalidCodexNativeAuthProfileBeforeRuntime(t *testing.T) {
	runtime := &fakeSandboxRuntime{}
	app := cli.New(cli.Options{SandboxRuntimes: map[string]sandbox.Runtime{"fake": runtime}})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"sandbox", "run", "--agent-auth", "native", "--agent-auth-profile", "../work",
		"--runtime", "fake", "--image", "fixture:test", "--", "codex",
	}, &stdout, &stderr)

	if code != 1 || !strings.Contains(stderr.String(), "agent auth profile must contain") {
		t.Fatalf("Run() code/stderr = %d/%q", code, stderr.String())
	}
	if len(runtime.eventsSnapshot()) != 0 {
		t.Fatalf("runtime events = %#v, want no runtime calls", runtime.eventsSnapshot())
	}
}

func TestRunSandboxRejectsNativeProfileWithoutNativeMode(t *testing.T) {
	app := cli.New(cli.Options{})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"sandbox", "run", "--agent-auth-profile", "work", "--image", "fixture:test", "--", "codex",
	}, &stdout, &stderr)

	if code != 1 || !strings.Contains(stderr.String(), "--agent-auth-profile requires --agent-auth native") {
		t.Fatalf("Run() code/stderr = %d/%q", code, stderr.String())
	}
}

func TestRunSandboxRejectsUserSuppliedCodexHomeForNativeAuth(t *testing.T) {
	root := t.TempDir()
	runtime := &fakeSandboxRuntime{}
	app := cli.New(cli.Options{
		Paths:           config.Paths{DataDir: filepath.Join(root, "data")},
		ProjectStartDir: t.TempDir(),
		SandboxRuntimes: map[string]sandbox.Runtime{"fake": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"sandbox", "run", "--agent-auth", "native",
		"--env", "CODEX_HOME=/user-controlled",
		"--runtime", "fake", "--image", "fixture:test", "--", "codex",
	}, &stdout, &stderr)

	if code != 1 || !strings.Contains(stderr.String(), "CODEX_HOME is reserved") {
		t.Fatalf("Run() code/stderr = %d/%q", code, stderr.String())
	}
	if strings.Join(runtime.eventsSnapshot(), ",") != "check" {
		t.Fatalf("runtime events = %#v, want preflight check only", runtime.eventsSnapshot())
	}
	if _, err := os.Stat(filepath.Join(root, "data", "agent-auth")); !os.IsNotExist(err) {
		t.Fatalf("native state was created after rejected environment: %v", err)
	}
}

func TestRunSandboxCanDisableAutomaticCodexAgentAuth(t *testing.T) {
	runtime := &fakeSandboxRuntime{}
	runtime.inspect = func(_ context.Context, spec sandbox.Spec) error {
		if strings.Join(spec.Command, " ") != "codex exec status" {
			return errors.New("Codex command was unexpectedly rewritten")
		}
		if _, ok := spec.Environment["ENVVAULT_CODEX_TOKEN"]; ok {
			return errors.New("Codex token was unexpectedly attached")
		}
		return nil
	}
	app := cli.New(cli.Options{
		ProjectStartDir: t.TempDir(),
		SandboxRuntimes: map[string]sandbox.Runtime{"fake": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"sandbox", "run", "--no-agent-auth",
		"--runtime", "fake", "--image", "fixture:test", "--", "codex", "exec", "status",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d; stderr=%q", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "agent-auth:") {
		t.Fatalf("stderr = %q, want no agent auth metadata", stderr.String())
	}
}

func TestRunSandboxRejectsConflictingAgentAuthFlags(t *testing.T) {
	app := cli.New(cli.Options{})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"sandbox", "run", "--agent-auth", "openai/dev", "--no-agent-auth",
		"--image", "fixture:test", "--", "codex",
	}, &stdout, &stderr)

	if code != 1 || !strings.Contains(stderr.String(), "--agent-auth and --no-agent-auth cannot be used together") {
		t.Fatalf("Run() code/stderr = %d/%q", code, stderr.String())
	}
}

func TestRunSandboxRejectsUserSuppliedCodexCapabilityEnvironment(t *testing.T) {
	profiles := fakeCLIProfileResolver{
		"openai/dev": compatibleCodexProfile("openai/dev", "openai-key/dev", "https://api.openai.com/v1"),
	}
	runtime := &fakeSandboxRuntime{}
	app := cli.New(cli.Options{
		ProjectStartDir: t.TempDir(),
		Profiles:        profiles,
		SandboxRuntimes: map[string]sandbox.Runtime{"fake": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"sandbox", "run", "--runtime", "fake", "--image", "fixture:test",
		"--env", "ENVVAULT_CODEX_TOKEN=user-controlled", "--", "codex",
	}, &stdout, &stderr)

	if code != 1 || !strings.Contains(stderr.String(), "ENVVAULT_CODEX_TOKEN is reserved") {
		t.Fatalf("Run() code/stderr = %d/%q", code, stderr.String())
	}
	if strings.Join(runtime.eventsSnapshot(), ",") != "check" {
		t.Fatalf("runtime events = %#v, want preflight check only", runtime.eventsSnapshot())
	}
}

func TestRunSandboxRejectsDirectReferenceBeforeContainerCreate(t *testing.T) {
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(context.Background(), keyring.CredentialValue("database/dev"), []byte("secret-canary")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	runtime := &fakeSandboxRuntime{}
	app := cli.New(cli.Options{
		ProjectStartDir: t.TempDir(),
		Secrets:         secrets,
		SandboxRuntimes: map[string]sandbox.Runtime{"fake": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"sandbox", "run", "--runtime", "fake", "--image", "fixture:test",
		"--env", "DATABASE_URL=envvault://database/dev",
		"--", "run",
	}, &stdout, &stderr)

	if code != 1 || !strings.Contains(stderr.String(), "direct credential references are not allowed") {
		t.Fatalf("Run() code/stderr = %d/%q", code, stderr.String())
	}
	if strings.Join(runtime.eventsSnapshot(), ",") != "check" {
		t.Fatalf("runtime events = %#v, want preflight check only", runtime.eventsSnapshot())
	}
	if strings.Contains(stdout.String()+stderr.String(), "secret-canary") {
		t.Fatalf("output leaked direct credential; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunSandboxAllowsExplicitMaterializedCredentialWithWarning(t *testing.T) {
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(context.Background(), keyring.CredentialValue("database/dev"), []byte("secret-canary")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	runtime := &fakeSandboxRuntime{}
	runtime.inspect = func(_ context.Context, spec sandbox.Spec) error {
		if spec.SecurityLevel != connection.SecurityMaterializedStatic || spec.Environment["DATABASE_URL"] != "secret-canary" {
			return errors.New("materialized credential was not explicitly delivered")
		}
		return nil
	}
	app := cli.New(cli.Options{
		ProjectStartDir: t.TempDir(),
		Secrets:         secrets,
		SandboxRuntimes: map[string]sandbox.Runtime{"fake": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"sandbox", "run", "--runtime", "fake", "--image", "fixture:test",
		"--allow-materialized-secrets",
		"--env", "DATABASE_URL=envvault://database/dev",
		"--", "run",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "security: materialized-static") || !strings.Contains(stderr.String(), "warning: raw credentials") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), "secret-canary") {
		t.Fatalf("CLI output leaked materialized credential; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunSandboxPassesInteractiveTTYStreamsToRuntime(t *testing.T) {
	input := strings.NewReader("interactive input\n")
	runtime := &fakeSandboxRuntime{}
	runtime.inspect = func(_ context.Context, spec sandbox.Spec) error {
		if !spec.Interactive || !spec.TTY {
			return errors.New("interactive TTY options were not passed to the runtime")
		}
		if spec.Stdin != input {
			return errors.New("sandbox stdin was not passed to the runtime")
		}
		return nil
	}
	app := cli.New(cli.Options{
		Stdin:           input,
		ProjectStartDir: t.TempDir(),
		SandboxRuntimes: map[string]sandbox.Runtime{"fake": runtime},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"sandbox", "run", "-it",
		"--runtime", "fake",
		"--image", "fixture:test",
		"--", "run",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d; stderr=%q", code, stderr.String())
	}
}

func TestRunSandboxHelpShowsInteractiveTTYFlags(t *testing.T) {
	app := cli.New(cli.Options{})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"sandbox", "run", "--help"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d; stderr=%q", code, stderr.String())
	}
	for _, want := range []string{"-i, --interactive", "-t, --tty", "--agent-auth", "--agent-auth-profile", "--no-agent-auth", "--outbound-profile", "--all", "all provider-proxy profile", "late-bound", "--agent-auth native", "sandbox run -it"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
}

func compatibleCodexProfile(name, credential, targetURL string) profile.Profile {
	return profile.Profile{
		Name:           name,
		Kind:           profile.KindProviderProxy,
		CredentialName: credential,
		AuthMode:       "bearer",
		Provider:       "openai-compatible",
		TargetURL:      targetURL,
		AllowedPaths:   []string{"/responses"},
		AllowedMethods: []string{http.MethodPost},
		LocalTokenTTL:  10 * time.Minute,
		ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
	}
}

func commandConfigOverride(command []string, key string) (string, bool) {
	for index := 1; index+1 < len(command); index++ {
		if command[index] != "-c" {
			continue
		}
		assignment := command[index+1]
		gotKey, value, ok := strings.Cut(assignment, "=")
		if ok && gotKey == key {
			if decoded, err := strconv.Unquote(value); err == nil {
				return decoded, true
			}
			return value, true
		}
		index++
	}
	return "", false
}

func containsCommaValue(raw, want string) bool {
	for _, value := range strings.Split(raw, ",") {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

type fakeSandboxRuntime struct {
	mu       sync.Mutex
	events   []string
	spec     sandbox.Spec
	exitCode int
	inspect  func(context.Context, sandbox.Spec) error
}

type fakeEgressSandboxRuntime struct {
	*fakeSandboxRuntime
	attach func(context.Context, connection.EgressClientConfig) (sandbox.EgressAttachment, error)
}

func (r *fakeEgressSandboxRuntime) AttachEgress(ctx context.Context, config connection.EgressClientConfig) (sandbox.EgressAttachment, error) {
	if r.attach == nil {
		return sandbox.EgressAttachment{}, errors.New("fake egress attachment is not configured")
	}
	return r.attach(ctx, config)
}

func (*fakeSandboxRuntime) Name() string { return "fake" }

func (r *fakeSandboxRuntime) Check(context.Context) error {
	r.addEvent("check")
	return nil
}

func (r *fakeSandboxRuntime) Create(_ context.Context, spec sandbox.Spec) (sandbox.Sandbox, error) {
	r.addEvent("create")
	r.mu.Lock()
	r.spec = spec
	r.mu.Unlock()
	return &fakeSandboxInstance{runtime: r}, nil
}

func (r *fakeSandboxRuntime) addEvent(event string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

func (r *fakeSandboxRuntime) eventsSnapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

type fakeSandboxInstance struct {
	runtime *fakeSandboxRuntime
}

func (*fakeSandboxInstance) ID() string { return "sbx-fake" }

func (s *fakeSandboxInstance) Start(context.Context) error {
	s.runtime.addEvent("start")
	return nil
}

func (s *fakeSandboxInstance) Wait(ctx context.Context) (sandbox.ExitResult, error) {
	s.runtime.addEvent("wait")
	s.runtime.mu.Lock()
	spec := s.runtime.spec
	inspect := s.runtime.inspect
	exitCode := s.runtime.exitCode
	s.runtime.mu.Unlock()
	if inspect != nil {
		if err := inspect(ctx, spec); err != nil {
			return sandbox.ExitResult{}, err
		}
	}
	return sandbox.ExitResult{Code: exitCode}, nil
}

func (s *fakeSandboxInstance) Stop(context.Context) error {
	s.runtime.addEvent("stop")
	return nil
}

func (s *fakeSandboxInstance) Remove(context.Context) error {
	s.runtime.addEvent("remove")
	return nil
}
