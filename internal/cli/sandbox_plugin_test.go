package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/cli"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/sandboxplugin"
)

func TestSandboxPluginServeUsesStdoutOnlyForProtocol(t *testing.T) {
	input := `{"protocol":"envvault.sandbox-plugin/v1","id":"health-1","method":"ping"}` + "\n"
	app := cli.New(cli.Options{
		Profiles: fakeCLIProfileResolver{},
		Secrets:  keyring.NewMemoryStore(),
		Stdin:    strings.NewReader(input),
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"sandbox", "plugin", "serve"}, &stdout, &stderr)

	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("Run() code/stderr = %d/%q", code, stderr.String())
	}
	var response sandboxplugin.ProtocolResponse
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &response); err != nil {
		t.Fatalf("Unmarshal(stdout) error = %v; stdout=%q", err, stdout.String())
	}
	if !response.OK || response.Status != "ready" {
		t.Fatalf("response = %#v", response)
	}
}

func TestSandboxPluginServeOpensAndCleansGatewayAtEOF(t *testing.T) {
	ctx := context.Background()
	const upstreamSecret = "ENVVAULT_CLI_PLUGIN_SECRET_CANARY"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	profiles := fakeCLIProfileResolver{
		"openai/codex": {
			Name:           "openai/codex",
			Kind:           profile.KindProviderProxy,
			CredentialName: "openai/key",
			AuthMode:       "bearer",
			Provider:       "openai-compatible",
			TargetURL:      target.URL,
			AllowedPaths:   []string{"/responses"},
			AllowedMethods: []string{http.MethodPost},
			LocalTokenTTL:  time.Minute,
			ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
		},
	}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue("openai/key"), []byte(upstreamSecret)); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	request := sandboxplugin.ProtocolRequest{
		Protocol: sandboxplugin.ProtocolVersion,
		ID:       "open-1",
		Method:   "open",
		Open: &sandboxplugin.OpenRequest{
			SandboxID: "openshell-sandbox-1",
			Bindings: []sandboxplugin.Binding{{
				Profile: "openai/codex",
				Outputs: []sandboxplugin.Output{
					{Environment: "OPENAI_BASE_URL", Part: sandboxplugin.OutputBaseURL},
					{Environment: "OPENAI_API_KEY", Part: sandboxplugin.OutputToken},
				},
			}},
		},
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Marshal(request) error = %v", err)
	}
	app := cli.New(cli.Options{
		Profiles: profiles,
		Secrets:  secrets,
		Stdin:    strings.NewReader(string(encoded) + "\n"),
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(ctx, []string{"sandbox", "plugin", "serve"}, &stdout, &stderr)

	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("Run() code/stderr = %d/%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), upstreamSecret) {
		t.Fatal("plugin protocol stdout leaked the upstream credential")
	}
	var response sandboxplugin.ProtocolResponse
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &response); err != nil {
		t.Fatalf("Unmarshal(stdout) error = %v", err)
	}
	if !response.OK || response.Lease == nil {
		t.Fatalf("response = %#v", response)
	}
	client := &http.Client{Timeout: 100 * time.Millisecond}
	req, err := http.NewRequest(http.MethodPost, response.Lease.Environment["OPENAI_BASE_URL"]+"/responses", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+response.Lease.Environment["OPENAI_API_KEY"])
	if afterEOF, err := client.Do(req); err == nil {
		_ = afterEOF.Body.Close()
		t.Fatal("gateway remained usable after plugin stdin reached EOF")
	}
}

func TestSandboxPluginServeRejectsFixedGatewayPort(t *testing.T) {
	app := cli.New(cli.Options{
		Profiles: fakeCLIProfileResolver{},
		Secrets:  keyring.NewMemoryStore(),
		Stdin:    strings.NewReader(""),
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"sandbox", "plugin", "serve", "--gateway-listen", "127.0.0.1:43123",
	}, &stdout, &stderr)

	if code != 1 || !strings.Contains(stderr.String(), "listen address must use port 0") || stdout.Len() != 0 {
		t.Fatalf("Run() code/stdout/stderr = %d/%q/%q", code, stdout.String(), stderr.String())
	}
}
