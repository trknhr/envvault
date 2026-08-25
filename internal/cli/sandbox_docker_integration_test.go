package cli_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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
	"github.com/trknhr/envvault/internal/sandbox"
	sandboxdocker "github.com/trknhr/envvault/internal/sandbox/docker"
)

func TestDockerSandboxBrokeredHTTPIntegration(t *testing.T) {
	if os.Getenv("ENVVAULT_DOCKER_TEST") != "1" {
		t.Skip("set ENVVAULT_DOCKER_TEST=1 to run the Docker sandbox integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	const upstreamSecret = "ENVVAULT_TEST_SECRET_DO_NOT_LOG_DOCKER"
	secretHash := sha256.Sum256([]byte(upstreamSecret))
	secretDigest := hex.EncodeToString(secretHash[:])
	var providerMu sync.Mutex
	var providerAuth, providerPath string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerMu.Lock()
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
			LocalTokenTTL:  time.Minute,
			ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
		},
	}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue("openai-key/dev"), []byte(upstreamSecret)); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	dockerRuntime := sandboxdocker.New(sandboxdocker.Options{})
	runtime := &metadataInspectingRuntime{delegate: dockerRuntime, forbidden: upstreamSecret}
	image := os.Getenv("ENVVAULT_DOCKER_TEST_IMAGE")
	if image == "" {
		image = "node:22-slim"
	}
	workspace := t.TempDir()
	app := cli.New(cli.Options{
		ProjectStartDir: workspace,
		Profiles:        profiles,
		Secrets:         secrets,
		SandboxRuntimes: map[string]sandbox.Runtime{"docker": runtime},
	})
	script := strings.Join([]string{
		`import { createHash } from "node:crypto";`,
		`import * as fs from "node:fs";`,
		`import * as path from "node:path";`,
		`const forbiddenDigest = "` + secretDigest + `";`,
		`const forbiddenLength = ` + strconv.Itoa(len(upstreamSecret)) + `;`,
		`const digest = value => createHash("sha256").update(value).digest("hex");`,
		`const containsSecret = value => {`,
		`  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(String(value));`,
		`  for (let offset = 0; offset + forbiddenLength <= buffer.length; offset++) {`,
		`    if (digest(buffer.subarray(offset, offset + forbiddenLength)) === forbiddenDigest) return true;`,
		`  }`,
		`  return false;`,
		`};`,
		`const scan = entry => {`,
		`  let info;`,
		`  try { info = fs.lstatSync(entry); } catch { return false; }`,
		`  if (info.isSymbolicLink()) return false;`,
		`  if (info.isDirectory()) return fs.readdirSync(entry).some(name => scan(path.join(entry, name)));`,
		`  if (!info.isFile()) return false;`,
		`  try { return containsSecret(fs.readFileSync(entry)); } catch { return false; }`,
		`};`,
		`const envLeak = Object.values(process.env).some(containsSecret);`,
		`const fileLeak = ["/workspace", "/home/envvault", "/tmp"].some(scan);`,
		`console.log("secret_env=" + envLeak);`,
		`console.log("secret_files=" + fileLeak);`,
		`if (envLeak || fileLeak) process.exit(8);`,
		`const headers = {Authorization: "Bearer " + process.env.API_TOKEN};`,
		`const deniedMethod = await fetch(process.env.API_BASE_URL + "/chat/completions", {method: "GET", headers});`,
		`if (deniedMethod.status !== 403) throw new Error("denied method unexpectedly succeeded");`,
		`const deniedPath = await fetch(process.env.API_BASE_URL + "/not-allowed", {method: "POST", headers});`,
		`if (deniedPath.status !== 403) throw new Error("denied path unexpectedly succeeded");`,
		`const allowed = await fetch(process.env.API_BASE_URL + "/chat/completions", {method: "POST", headers});`,
		`console.log("status=" + allowed.status);`,
		`if (allowed.status !== 201) process.exit(9);`,
	}, "\n")
	var stdout, stderr bytes.Buffer

	code := app.Run(ctx, []string{
		"sandbox", "run", "--runtime", "docker", "--image", image,
		"--env", "API_BASE_URL=envvault://openai/dev/base-url",
		"--env", "API_TOKEN=envvault://openai/dev/token",
		"--", "node", "--input-type=module", "--eval", script,
	}, &stdout, &stderr)

	combinedOutput := stdout.String() + stderr.String()
	if strings.Contains(combinedOutput, upstreamSecret) || strings.Contains(combinedOutput, "envvault-local-") {
		t.Fatal("CLI output leaked an upstream credential or session capability")
	}
	if code != 0 {
		t.Fatalf("Run() code = %d", code)
	}
	if !strings.Contains(stdout.String(), "status=201") ||
		!strings.Contains(stdout.String(), "secret_env=false") ||
		!strings.Contains(stdout.String(), "secret_files=false") {
		t.Fatal("fixture did not confirm proxy success and raw-secret absence")
	}
	providerMu.Lock()
	authOK := providerAuth == "Bearer "+upstreamSecret
	pathOK := providerPath == "/v1/chat/completions"
	providerMu.Unlock()
	if !authOK || !pathOK {
		t.Fatalf("provider request mismatch (auth_ok=%t, path_ok=%t)", authOK, pathOK)
	}
	sandboxID := metadataValue(stderr.String(), "sandbox: ")
	if sandboxID == "" {
		t.Fatal("stderr missing sandbox id")
	}
	output, err := exec.CommandContext(ctx, "docker", "ps", "-aq", "--filter", "label=io.envvault.sandbox="+sandboxID).Output()
	if err != nil {
		t.Fatalf("docker ps error = %v", err)
	}
	if strings.TrimSpace(string(output)) != "" {
		t.Fatal("sandbox container remained after run")
	}
	entries, err := os.ReadDir(workspace)
	if err != nil {
		t.Fatalf("ReadDir(workspace) error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatal("sandbox left temporary files in the workspace")
	}
}

func TestDockerSandboxURLPreservingOutboundIntegration(t *testing.T) {
	if os.Getenv("ENVVAULT_DOCKER_TEST") != "1" {
		t.Skip("set ENVVAULT_DOCKER_TEST=1 to run the Docker sandbox integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	const upstreamSecret = "ENVVAULT_OUTBOUND_SECRET_DO_NOT_LOG_DOCKER"
	secretHash := sha256.Sum256([]byte(upstreamSecret))
	secretDigest := hex.EncodeToString(secretHash[:])
	var providerMu sync.Mutex
	var providerAuth, providerPath string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerMu.Lock()
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
			LocalTokenTTL:  time.Minute,
			ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
		},
	}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue("gemini-key/dev"), []byte(upstreamSecret)); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	dockerRuntime := sandboxdocker.New(sandboxdocker.Options{})
	runtime := &metadataInspectingRuntime{delegate: dockerRuntime, forbidden: upstreamSecret}
	image := os.Getenv("ENVVAULT_DOCKER_TEST_IMAGE")
	if image == "" {
		image = "node:22-slim"
	}
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, ".env"), []byte("GEMINI_API_KEY=envvault://gemini-key/dev\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(.env) error = %v", err)
	}
	app := cli.New(cli.Options{
		ProjectStartDir: workspace,
		Profiles:        profiles,
		Secrets:         secrets,
		SandboxRuntimes: map[string]sandbox.Runtime{"docker": runtime},
	})
	script := strings.Join([]string{
		`import { createHash } from "node:crypto";`,
		`import * as fs from "node:fs";`,
		`const forbiddenDigest = "` + secretDigest + `";`,
		`const forbiddenLength = ` + strconv.Itoa(len(upstreamSecret)) + `;`,
		`const digest = value => createHash("sha256").update(value).digest("hex");`,
		`const containsSecret = value => {`,
		`  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(String(value));`,
		`  for (let offset = 0; offset + forbiddenLength <= buffer.length; offset++) {`,
		`    if (digest(buffer.subarray(offset, offset + forbiddenLength)) === forbiddenDigest) return true;`,
		`  }`,
		`  return false;`,
		`};`,
		`if (Object.values(process.env).some(containsSecret)) process.exit(8);`,
		`if (!process.env.HTTP_PROXY || process.env.NODE_USE_ENV_PROXY !== "1") process.exit(9);`,
		`if (!fs.existsSync(process.env.NODE_EXTRA_CA_CERTS)) process.exit(10);`,
		`const dotenv = fs.readFileSync("/workspace/.env", "utf8").trim();`,
		`const prefix = "GEMINI_API_KEY=";`,
		`if (!dotenv.startsWith(prefix)) process.exit(11);`,
		`const geminiApiKey = dotenv.slice(prefix.length);`,
		`if (geminiApiKey !== "envvault://gemini-key/dev") process.exit(11);`,
		`const headers = {Authorization: "Bearer " + geminiApiKey};`,
		`const denied = await fetch(process.argv[1] + "/v1/not-allowed", {method: "POST", headers});`,
		`if (denied.status !== 403) process.exit(11);`,
		`const allowed = await fetch(process.argv[1] + "/v1/models/generateContent", {method: "POST", headers});`,
		`console.log("status=" + allowed.status);`,
		`if (allowed.status !== 202) process.exit(12);`,
	}, "\n")
	var stdout, stderr bytes.Buffer

	code := app.Run(ctx, []string{
		"sandbox", "run", "--runtime", "docker", "--image", image,
		"--outbound-profile", "gemini/dev",
		"--", "node", "--input-type=module", "--eval", script, target.URL,
	}, &stdout, &stderr)

	combinedOutput := stdout.String() + stderr.String()
	if strings.Contains(combinedOutput, upstreamSecret) {
		t.Fatal("CLI output leaked an upstream credential")
	}
	if code != 0 {
		t.Fatalf("Run() code = %d; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "status=202") || !strings.Contains(stderr.String(), "outbound: proxy-environment via gemini/dev") {
		t.Fatalf("fixture output = %q/%q", stdout.String(), stderr.String())
	}
	providerMu.Lock()
	authOK := providerAuth == "Bearer "+upstreamSecret
	pathOK := providerPath == "/v1/models/generateContent"
	providerMu.Unlock()
	if !authOK || !pathOK {
		t.Fatalf("provider request mismatch (auth_ok=%t path_ok=%t)", authOK, pathOK)
	}
	sandboxID := metadataValue(stderr.String(), "sandbox: ")
	if sandboxID == "" {
		t.Fatal("stderr missing sandbox id")
	}
	output, err := exec.CommandContext(ctx, "docker", "ps", "-aq", "--filter", "label=io.envvault.sandbox="+sandboxID).Output()
	if err != nil {
		t.Fatalf("docker ps error = %v", err)
	}
	if strings.TrimSpace(string(output)) != "" {
		t.Fatal("sandbox container remained after run")
	}
}

func TestDockerSandboxCodexNativeAuthIntegration(t *testing.T) {
	if os.Getenv("ENVVAULT_DOCKER_TEST") != "1" {
		t.Skip("set ENVVAULT_DOCKER_TEST=1 to run the Docker sandbox integration test")
	}
	image := strings.TrimSpace(os.Getenv("ENVVAULT_CODEX_TEST_IMAGE"))
	if image == "" {
		t.Skip("set ENVVAULT_CODEX_TEST_IMAGE to an image containing Codex CLI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	app := cli.New(cli.Options{
		Paths:           config.Paths{DataDir: dataDir},
		ProjectStartDir: t.TempDir(),
		SandboxRuntimes: map[string]sandbox.Runtime{"docker": sandboxdocker.New(sandboxdocker.Options{})},
	})
	var stdout, stderr bytes.Buffer

	code := app.Run(ctx, []string{
		"sandbox", "run",
		"--agent-auth", "native",
		"--agent-auth-profile", "integration",
		"--runtime", "docker",
		"--image", image,
		"--", "codex", "--version",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "codex-cli") ||
		!strings.Contains(stderr.String(), "agent-auth: codex native (profile integration)") ||
		!strings.Contains(stderr.String(), "security: materialized-static") {
		t.Fatalf("stdout/stderr = %q/%q", stdout.String(), stderr.String())
	}
	state := filepath.Join(dataDir, "agent-auth", "codex", "integration")
	info, err := os.Stat(state)
	if err != nil || !info.IsDir() {
		t.Fatalf("native state = %#v/%v", info, err)
	}
}

type metadataInspectingRuntime struct {
	delegate  *sandboxdocker.Runtime
	forbidden string
}

func (*metadataInspectingRuntime) Name() string { return "docker" }

func (r *metadataInspectingRuntime) Check(ctx context.Context) error {
	return r.delegate.Check(ctx)
}

func (r *metadataInspectingRuntime) GatewayAccess() sandbox.GatewayAccess {
	return r.delegate.GatewayAccess()
}

func (r *metadataInspectingRuntime) AttachEgress(ctx context.Context, config connection.EgressClientConfig) (sandbox.EgressAttachment, error) {
	return r.delegate.AttachEgress(ctx, config)
}

func (r *metadataInspectingRuntime) Create(ctx context.Context, spec sandbox.Spec) (sandbox.Sandbox, error) {
	for _, value := range spec.Environment {
		if strings.Contains(value, r.forbidden) {
			return nil, errors.New("sandbox specification contains an upstream credential")
		}
	}
	for _, argument := range spec.Command {
		if strings.Contains(argument, r.forbidden) {
			return nil, errors.New("sandbox command contains an upstream credential")
		}
	}
	instance, err := r.delegate.Create(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &metadataInspectingSandbox{Sandbox: instance, forbidden: r.forbidden}, nil
}

type metadataInspectingSandbox struct {
	sandbox.Sandbox
	forbidden string
}

func (s *metadataInspectingSandbox) Start(ctx context.Context) error {
	if err := s.Sandbox.Start(ctx); err != nil {
		return err
	}
	containerID, err := exec.CommandContext(ctx, "docker", "ps", "-aq", "--filter", "label=io.envvault.sandbox="+s.ID()).Output()
	if err != nil || strings.TrimSpace(string(containerID)) == "" {
		return errors.New("cannot inspect Docker sandbox metadata")
	}
	metadata, err := exec.CommandContext(ctx, "docker", "inspect", strings.TrimSpace(string(containerID))).Output()
	if err != nil {
		return errors.New("cannot inspect Docker sandbox metadata")
	}
	if bytes.Contains(metadata, []byte(s.forbidden)) {
		return errors.New("Docker sandbox metadata contains an upstream credential")
	}
	return nil
}

func metadataValue(output, prefix string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}
