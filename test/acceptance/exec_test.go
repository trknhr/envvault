package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/cli"
	"github.com/trknhr/credlease/internal/issuer"
	"github.com/trknhr/credlease/internal/issuer/talosruntime"
	"github.com/trknhr/credlease/internal/process"
	"github.com/trknhr/credlease/internal/profile"
	runtimetalos "github.com/trknhr/credlease/internal/runtime/talos"
	verifierpkg "github.com/trknhr/credlease/pkg/verifier"
)

func TestExecResolvesReferenceAndDoesNotPassParentAuthority(t *testing.T) {
	repoRoot := findRepoRoot(t)
	inspectChild := buildFixture(t, repoRoot, "inspect-child")
	projectRoot := t.TempDir()
	envFile := filepath.Join(projectRoot, ".env")
	originalEnv := "TOKEN=credlease://backend-a/dev\nPLAIN=file-value\n"
	if err := os.WriteFile(envFile, []byte(originalEnv), 0o600); err != nil {
		t.Fatalf("WriteFile(.env) error = %v", err)
	}

	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	key := newAcceptanceRSAKey(t)
	tokenIssuer := &signingAcceptanceIssuer{
		key:    key,
		issuer: "credlease-local:test-install",
		now:    now,
	}
	app := newExecApp(projectRoot, fakeProfiles(), tokenIssuer)
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"exec",
		"--env-file", envFile,
		"--", inspectChild, "arg1",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	var child inspectSnapshot
	if err := json.Unmarshal(stdout.Bytes(), &child); err != nil {
		t.Fatalf("Unmarshal(inspect-child) error = %v; stdout=%q", err, stdout.String())
	}
	if got := child.Env["TOKEN"]; got == "" || got != tokenIssuer.token {
		t.Fatalf("child TOKEN = %q, want issued JWT", got)
	}
	tokenVerifier, err := verifierpkg.New(verifierpkg.Options{
		JWKS:          acceptanceJWKSForRSA(t, &key.PublicKey),
		Issuer:        "credlease-local:test-install",
		Resource:      "https://api.dev.example.com",
		RequireIssuer: true,
		Now:           func() time.Time { return now },
		ClockSkew:     time.Second,
	})
	if err != nil {
		t.Fatalf("verifier.New() error = %v", err)
	}
	if _, err := tokenVerifier.Verify(context.Background(), child.Env["TOKEN"], verifierpkg.Requirements{
		Scopes:  []string{"repository:read"},
		Purpose: "process",
	}); err != nil {
		t.Fatalf("child TOKEN is not a verifiable process JWT: %v", err)
	}
	if got := child.Env["PLAIN"]; got != "file-value" {
		t.Fatalf("child PLAIN = %q, want file value", got)
	}
	for _, key := range []string{
		"CREDLEASE_TALOS_HMAC_SECRET",
		"CREDLEASE_TALOS_SIGNING_KEY",
		"CREDLEASE_PROFILE_PARENT_KEY",
	} {
		if _, ok := child.Env[key]; ok {
			t.Fatalf("child environment leaked %s", key)
		}
	}
	if strings.Contains(stdout.String(), "raw-parent-secret") || strings.Contains(stderr.String(), "raw-parent-secret") {
		t.Fatalf("raw parent secret leaked; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if len(tokenIssuer.grants) != 1 {
		t.Fatalf("issuer grants = %d, want 1", len(tokenIssuer.grants))
	}
	assertFileContent(t, envFile, originalEnv)
}

func TestExecUnknownProfileFailsClosedWithoutParentFallback(t *testing.T) {
	projectRoot := t.TempDir()
	envFile := filepath.Join(projectRoot, ".env")
	if err := os.WriteFile(envFile, []byte("TOKEN=credlease://unknown/dev\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(.env) error = %v", err)
	}

	tokenIssuer := &fakeIssuer{token: "leased-jwt"}
	app := newExecApp(projectRoot, fakeProfiles(), tokenIssuer)
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"exec",
		"--env-file", envFile,
		"--", buildFixture(t, findRepoRoot(t), "inspect-child"),
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), string(clerr.ProfileNotFound)) {
		t.Fatalf("stderr = %q, want profile not found", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want child not started", stdout.String())
	}
	if len(tokenIssuer.grants) != 0 {
		t.Fatalf("issuer grants = %d, want 0", len(tokenIssuer.grants))
	}
	if strings.Contains(stderr.String(), "raw-parent-secret") {
		t.Fatalf("stderr leaked parent fallback secret: %q", stderr.String())
	}
}

func TestExecStartsChildAfterOnDemandRuntimeStops(t *testing.T) {
	repoRoot := findRepoRoot(t)
	inspectChild := buildFixture(t, repoRoot, "inspect-child")
	projectRoot := t.TempDir()
	envFile := filepath.Join(projectRoot, ".env")
	if err := os.WriteFile(envFile, []byte("TOKEN=credlease://backend-a/dev\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(.env) error = %v", err)
	}

	runtime := newAcceptanceTalosRuntime(t)
	tokenIssuer := talosRuntimeIssuer{
		parentKey: "parent-secret",
		client: talosruntime.Client{
			Runtime: runtime,
			HTTP:    runtime.Client(),
		},
	}
	app := newExecAppWithParentEnv(projectRoot, fakeProfiles(), tokenIssuer,
		"CREDLEASE_INSPECT_PORTS="+runtime.Address(),
	)
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"exec",
		"--env-file", envFile,
		"--", inspectChild,
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	var child inspectSnapshot
	if err := json.Unmarshal(stdout.Bytes(), &child); err != nil {
		t.Fatalf("Unmarshal(inspect-child) error = %v; stdout=%q", err, stdout.String())
	}
	if child.Env["TOKEN"] != "leased-jwt" {
		t.Fatalf("child TOKEN = %q, want leased-jwt", child.Env["TOKEN"])
	}
	starts, stops := runtime.Counts()
	if starts != 1 || stops != 1 {
		t.Fatalf("runtime starts/stops = %d/%d, want 1/1", starts, stops)
	}
	childStartedAt, err := time.Parse(time.RFC3339Nano, child.StartedAt)
	if err != nil {
		t.Fatalf("parse child started_at %q: %v", child.StartedAt, err)
	}
	stoppedAt := runtime.StoppedAt()
	if stoppedAt.IsZero() {
		t.Fatal("runtime stopped_at was not recorded")
	}
	if childStartedAt.Before(stoppedAt) {
		t.Fatalf("child started at %s before runtime stopped at %s", childStartedAt, stoppedAt)
	}
	status, ok := child.Ports[runtime.Address()]
	if !ok {
		t.Fatalf("child port checks = %#v, want %q", child.Ports, runtime.Address())
	}
	if status.Reachable {
		t.Fatalf("runtime address %s was reachable from child", runtime.Address())
	}
}

func TestExecRejectsQueryReferenceBeforeStartingChild(t *testing.T) {
	projectRoot := t.TempDir()
	envFile := filepath.Join(projectRoot, ".env")
	if err := os.WriteFile(envFile, []byte("TOKEN=credlease://backend-a/dev?scope=admin&ttl=24h\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(.env) error = %v", err)
	}

	app := newExecApp(projectRoot, fakeProfiles(), &fakeIssuer{token: "leased-jwt"})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"exec",
		"--env-file", envFile,
		"--", buildFixture(t, findRepoRoot(t), "inspect-child"),
	}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), string(clerr.ReferenceInvalid)) {
		t.Fatalf("stderr = %q, want reference invalid", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want child not started", stdout.String())
	}
	if strings.Contains(stderr.String(), "scope=admin") || strings.Contains(stderr.String(), "ttl=24h") {
		t.Fatalf("stderr leaked rejected reference details: %q", stderr.String())
	}
}

func TestExecPropagatesChildExitCode(t *testing.T) {
	repoRoot := findRepoRoot(t)
	exitCode := buildFixture(t, repoRoot, "exit-code")
	projectRoot := t.TempDir()
	app := newExecApp(projectRoot, fakeProfiles(), &fakeIssuer{token: "leased-jwt"})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{
		"exec",
		"--", exitCode, "--code", "42",
	}, &stdout, &stderr)

	if code != 42 {
		t.Fatalf("Run() code = %d, want child exit code 42; stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q, want both empty", stdout.String(), stderr.String())
	}
}

type inspectSnapshot struct {
	Env       map[string]string            `json:"env"`
	StartedAt string                       `json:"started_at"`
	Ports     map[string]inspectPortStatus `json:"ports"`
}

type inspectPortStatus struct {
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
}

type fakeProfileResolver map[string]profile.Profile

func (r fakeProfileResolver) Profile(name string) (profile.Profile, error) {
	p, ok := r[name]
	if !ok {
		return profile.Profile{}, clerr.New(clerr.ProfileNotFound, name)
	}
	return p, nil
}

type fakeIssuer struct {
	token  string
	grants []issuer.Grant
}

func (f *fakeIssuer) Issue(_ context.Context, grant issuer.Grant) (issuer.Credential, error) {
	f.grants = append(f.grants, grant)
	return issuer.Credential{
		AccessToken: f.token,
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(grant.TTL),
		Scopes:      append([]string(nil), grant.Scopes...),
	}, nil
}

type talosRuntimeIssuer struct {
	client    talosruntime.Client
	parentKey string
}

func (i talosRuntimeIssuer) Issue(ctx context.Context, grant issuer.Grant) (issuer.Credential, error) {
	return i.client.DeriveJWT(ctx, i.parentKey, grant)
}

type acceptanceTalosRuntime struct {
	server    *httptest.Server
	address   string
	mu        sync.Mutex
	starts    int
	stops     int
	stoppedAt time.Time
}

func newAcceptanceTalosRuntime(t *testing.T) *acceptanceTalosRuntime {
	t.Helper()

	runtime := &acceptanceTalosRuntime{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(runtime.handle))
	runtime.server = server
	runtime.address = server.Listener.Addr().String()
	t.Cleanup(server.Close)

	return runtime
}

func (r *acceptanceTalosRuntime) Client() *http.Client {
	return r.server.Client()
}

func (r *acceptanceTalosRuntime) Address() string {
	return r.address
}

func (r *acceptanceTalosRuntime) Counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.starts, r.stops
}

func (r *acceptanceTalosRuntime) StoppedAt() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stoppedAt
}

func (r *acceptanceTalosRuntime) Start(context.Context) (runtimetalos.Endpoint, error) {
	r.mu.Lock()
	r.starts++
	r.mu.Unlock()

	r.server.Start()
	return runtimetalos.Endpoint{URL: r.server.URL, Address: r.address}, nil
}

func (r *acceptanceTalosRuntime) Stop(context.Context) error {
	r.server.Close()

	r.mu.Lock()
	defer r.mu.Unlock()
	r.stops++
	r.stoppedAt = time.Now().UTC()
	return nil
}

func (r *acceptanceTalosRuntime) handle(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost || req.URL.Path != "/v2alpha1/admin/apiKeys:derive" {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"token":{"token":"leased-jwt"}}`))
}

func newExecApp(projectRoot string, profiles fakeProfileResolver, tokenIssuer issuer.Issuer) cli.App {
	return newExecAppWithParentEnv(projectRoot, profiles, tokenIssuer)
}

func newExecAppWithParentEnv(projectRoot string, profiles fakeProfileResolver, tokenIssuer issuer.Issuer, extraParentEnv ...string) cli.App {
	parent := append([]string{}, os.Environ()...)
	parent = append(parent,
		"TOKEN=raw-parent-secret",
		"CREDLEASE_TALOS_HMAC_SECRET=hmac-secret-canary",
		"CREDLEASE_TALOS_SIGNING_KEY=signing-secret-canary",
		"CREDLEASE_PROFILE_PARENT_KEY=parent-secret-canary",
	)
	parent = append(parent, extraParentEnv...)
	return cli.New(cli.Options{
		ParentEnv:       parent,
		ProjectStartDir: projectRoot,
		Profiles:        profiles,
		Issuer:          tokenIssuer,
		Runner:          process.Runner{},
	})
}

func fakeProfiles() fakeProfileResolver {
	return fakeProfileResolver{
		"backend-a/dev": {
			Name:        "backend-a/dev",
			Kind:        profile.KindProcess,
			Resource:    "https://api.dev.example.com",
			Scopes:      []string{"repository:read"},
			TokenTTL:    10 * time.Minute,
			MaxTokenTTL: 30 * time.Minute,
		},
	}
}

func buildFixture(t *testing.T, repoRoot, name string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), name)
	if strings.Contains(name, string(os.PathSeparator)) {
		t.Fatalf("fixture name must be a single path element: %q", name)
	}
	cmd := exec.Command("go", "build", "-o", out, filepath.Join(repoRoot, "test", "fixtures", name))
	cmd.Dir = repoRoot
	body, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build fixture %s: %v\n%s", name, err, body)
	}
	return out
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root with go.mod not found")
		}
		dir = parent
	}
}

func assertFileContent(t *testing.T, path string, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}
