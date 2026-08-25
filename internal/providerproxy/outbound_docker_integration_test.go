package providerproxy_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/projectbinding"
	"github.com/trknhr/envvault/internal/providerproxy"
	"github.com/trknhr/envvault/internal/sandbox"
	sandboxdocker "github.com/trknhr/envvault/internal/sandbox/docker"
)

func TestDockerOutboundHTTPSMITMIntegration(t *testing.T) {
	if os.Getenv("ENVVAULT_DOCKER_TEST") != "1" {
		t.Skip("set ENVVAULT_DOCKER_TEST=1 to run the Docker outbound integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	const upstreamSecret = "ENVVAULT_HTTPS_OUTBOUND_SECRET_DO_NOT_LOG_DOCKER"
	var providerMu sync.Mutex
	var providerAuth, providerPath string
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerMu.Lock()
		providerAuth = r.Header.Get("Authorization")
		providerPath = r.URL.Path
		providerMu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "created")
	}))
	defer target.Close()

	p := providerProfile(target.URL + "/v1")
	p.CredentialName = "https-outbound/dev"
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue(p.CredentialName), []byte(upstreamSecret)); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	lease, err := (providerproxy.OutboundResolver{
		Profiles:      testProfiles{p.Name: p},
		Secrets:       secrets,
		HTTP:          target.Client(),
		ListenAddress: "0.0.0.0:0",
		AdvertiseHost: "host.docker.internal",
	}).Open(ctx, []string{p.Name}, projectbinding.Identity{}, "docker-test")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	runtime := sandboxdocker.New(sandboxdocker.Options{})
	attachment, err := runtime.AttachEgress(ctx, lease.ClientConfig())
	if err != nil {
		_ = lease.Close(context.Background())
		t.Fatalf("AttachEgress() error = %v", err)
	}
	resources := append([]sandbox.Resource(nil), attachment.Resources...)
	resources = append(resources, lease)
	image := strings.TrimSpace(os.Getenv("ENVVAULT_DOCKER_TEST_IMAGE"))
	if image == "" {
		image = "node:22-slim"
	}
	var stdout, stderr bytes.Buffer
	result, err := (sandbox.Orchestrator{}).Run(ctx, sandbox.RunRequest{
		Runtime: runtime,
		Spec: sandbox.Spec{
			Image:            image,
			Command:          []string{"node", "--input-type=module", "--eval", `const response = await fetch(process.argv[1], {method: "POST", headers: {Authorization: "Bearer " + process.env.PROVIDER_API_KEY}}); console.log("status=" + response.status); if (response.status !== 201) process.exit(7);`, target.URL + "/v1/chat/completions"},
			WorkingDirectory: "/workspace",
			Environment: func() map[string]string {
				environment := make(map[string]string, len(attachment.Environment)+1)
				for key, value := range attachment.Environment {
					environment[key] = value
				}
				environment["PROVIDER_API_KEY"] = "envvault://https-outbound/dev"
				return environment
			}(),
			Workspace: sandbox.WorkspaceMount{
				Source: t.TempDir(),
				Target: "/workspace",
			},
			Mounts: attachment.Mounts,
			Resources: sandbox.ResourceLimits{
				PIDs:        256,
				MemoryBytes: 512 << 20,
				CPUs:        1,
			},
			Network:       sandbox.NetworkAttachment{Mode: sandbox.NetworkBridge},
			SecurityLevel: connection.SecurityBrokered,
			Stdout:        &stdout,
			Stderr:        &stderr,
		},
		Resources: resources,
	})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("Run() result/error = %#v/%v; stdout=%q stderr=%q", result, err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "status=201") || strings.Contains(stdout.String()+stderr.String(), upstreamSecret) {
		t.Fatalf("stdout/stderr = %q/%q", stdout.String(), stderr.String())
	}
	providerMu.Lock()
	authOK := providerAuth == "Bearer "+upstreamSecret
	pathOK := providerPath == "/v1/chat/completions"
	providerMu.Unlock()
	if !authOK || !pathOK {
		t.Fatalf("provider request mismatch (auth_ok=%t path_ok=%t)", authOK, pathOK)
	}
}
