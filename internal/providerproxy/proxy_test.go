package providerproxy_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/projectbinding"
	"github.com/trknhr/envvault/internal/providerproxy"
)

func TestServerForwardsAllowedRequestWithProviderBearer(t *testing.T) {
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	var providerMu sync.Mutex
	var gotAuth, gotPath, gotQuery, gotBody string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerMu.Lock()
		defer providerMu.Unlock()
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll() error = %v", err)
		}
		gotBody = string(body)
		w.Header().Set("X-Provider", "ok")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer target.Close()
	server := startTestServer(t, providerProfile(target.URL+"/v1"), "sk-real", "envvault-local-test", now)
	defer closeTestServer(t, server)

	req, err := http.NewRequest(http.MethodPost, server.BaseURL()+"/chat/completions?model=test", strings.NewReader(`{"messages":[]}`))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer envvault-local-test")
	req.Header.Set("Content-Type", "application/json")
	resp, err := target.Client().Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(response) error = %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Provider") != "ok" {
		t.Fatalf("X-Provider = %q, want ok", resp.Header.Get("X-Provider"))
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("body = %q", body)
	}
	providerMu.Lock()
	authOK := gotAuth == "Bearer sk-real"
	gotPathSnapshot := gotPath
	gotQuerySnapshot := gotQuery
	gotBodySnapshot := gotBody
	providerMu.Unlock()
	if !authOK {
		t.Fatal("provider Authorization did not contain the expected credential")
	}
	if gotPathSnapshot != "/v1/chat/completions" {
		t.Fatalf("provider path = %q, want /v1/chat/completions", gotPathSnapshot)
	}
	if gotQuerySnapshot != "model=test" {
		t.Fatalf("provider query = %q, want model=test", gotQuerySnapshot)
	}
	if gotBodySnapshot != `{"messages":[]}` {
		t.Fatalf("provider body = %q", gotBodySnapshot)
	}
}

func TestServerRejectsInvalidTokenAndPolicy(t *testing.T) {
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("target should not be called for rejected requests")
	}))
	defer target.Close()
	server := startTestServer(t, providerProfile(target.URL), "sk-real", "envvault-local-test", now)
	defer closeTestServer(t, server)

	tests := []struct {
		name   string
		method string
		path   string
		token  string
		want   int
	}{
		{name: "missing token", method: http.MethodPost, path: "/chat/completions", want: http.StatusUnauthorized},
		{name: "wrong token", method: http.MethodPost, path: "/chat/completions", token: "wrong", want: http.StatusUnauthorized},
		{name: "method denied", method: http.MethodGet, path: "/chat/completions", token: "envvault-local-test", want: http.StatusForbidden},
		{name: "path denied", method: http.MethodPost, path: "/models", token: "envvault-local-test", want: http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, server.BaseURL()+tt.path, nil)
			if err != nil {
				t.Fatalf("NewRequest() error = %v", err)
			}
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			resp, err := target.Client().Do(req)
			if err != nil {
				t.Fatalf("Do() error = %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tt.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}
}

func TestEnvResolverRewritesReferencesToLocalProxy(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	var providerMu sync.Mutex
	var providerAuth string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerMu.Lock()
		providerAuth = r.Header.Get("Authorization")
		providerMu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "accepted")
	}))
	defer target.Close()
	profiles := testProfiles{"openai/dev": providerProfile(target.URL)}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.ProviderAPIKey("openai/dev"), []byte("sk-real")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	resolver := &providerproxy.EnvResolver{
		Profiles: profiles,
		Secrets:  secrets,
		HTTP:     target.Client(),
		Now:      func() time.Time { return now },
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := resolver.Close(shutdownCtx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	baseURL, err := resolver.ResolveReference(ctx, envref.Reference{Profile: "openai/dev", Part: envref.PartBaseURL}, projectbinding.Identity{})
	if err != nil {
		t.Fatalf("ResolveReference(base-url) error = %v", err)
	}
	localToken, err := resolver.ResolveReference(ctx, envref.Reference{Profile: "openai/dev", Part: envref.PartToken}, projectbinding.Identity{})
	if err != nil {
		t.Fatalf("ResolveReference(token) error = %v", err)
	}
	if !strings.HasPrefix(baseURL, "http://127.0.0.1:") {
		t.Fatalf("baseURL = %q, want localhost proxy", baseURL)
	}
	if !strings.HasPrefix(localToken, "envvault-local-") {
		t.Fatal("resolver did not return a local proxy capability")
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/chat/completions", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+localToken)
	resp, err := target.Client().Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	providerMu.Lock()
	authOK := providerAuth == "Bearer sk-real"
	providerMu.Unlock()
	if !authOK {
		t.Fatal("provider Authorization did not contain the expected credential")
	}
}

func TestEnvResolverResolveProxyBindsGrantToSubjectAndRedactsCapability(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	adapter := &captureAdapter{now: now}
	resolver := &providerproxy.EnvResolver{
		Profiles:  testProfiles{"openai/dev": providerProfile("https://api.example.test/v1")},
		Adapter:   adapter,
		SubjectID: "sandbox-123",
		Now:       func() time.Time { return now },
	}
	defer func() {
		if err := resolver.Close(context.Background()); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	lease, err := resolver.ResolveProxy(ctx, "openai/dev", projectbinding.Identity{})
	if err != nil {
		t.Fatalf("ResolveProxy() error = %v", err)
	}
	if adapter.request.Grant.SubjectID != "sandbox-123" {
		t.Fatalf("grant subject = %q, want sandbox-123", adapter.request.Grant.SubjectID)
	}
	if lease.BaseURL != "http://127.0.0.1:43123/openai/dev" || lease.Token != "temporary-capability" {
		t.Fatalf("ResolveProxy() returned unexpected delivery metadata")
	}
	formatted := fmt.Sprintf("%v %#v", lease, lease)
	if strings.Contains(formatted, "temporary-capability") {
		t.Fatal("formatted proxy lease leaked its session capability")
	}
}

type captureAdapter struct {
	now     time.Time
	request connection.AdapterStartRequest
}

func (*captureAdapter) Protocol() connection.ProtocolType { return connection.ProtocolHTTP }

func (*captureAdapter) Validate(connection.Policy) error { return nil }

func (a *captureAdapter) Start(_ context.Context, request connection.AdapterStartRequest) (connection.AdapterLease, error) {
	a.request = request
	return captureAdapterLease{expiresAt: a.now.Add(time.Minute)}, nil
}

type captureAdapterLease struct {
	expiresAt time.Time
}

func (captureAdapterLease) Endpoint() connection.Endpoint {
	return connection.Endpoint{Network: "tcp", Address: "127.0.0.1:43123"}
}

func (l captureAdapterLease) ExpiresAt() time.Time { return l.expiresAt }

func (captureAdapterLease) BaseURL() string { return "http://127.0.0.1:43123/openai/dev" }

func (captureAdapterLease) Token() string { return "temporary-capability" }

func (captureAdapterLease) Close(context.Context) error { return nil }

func TestEnvResolverResolvesDefaultReferenceToCredentialValue(t *testing.T) {
	ctx := context.Background()
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue("openai/dev"), []byte("sk-real")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	resolver := &providerproxy.EnvResolver{Secrets: secrets}

	value, err := resolver.ResolveReference(ctx, envref.Reference{Profile: "openai/dev", Part: envref.PartDefault}, projectbinding.Identity{})
	if err != nil {
		t.Fatalf("ResolveReference() error = %v", err)
	}
	if value != "sk-real" {
		t.Fatal("default reference did not resolve to the expected credential")
	}
}

type testProfiles map[string]profile.Profile

func (p testProfiles) Profile(name string) (profile.Profile, error) {
	return p[name], nil
}

func startTestServer(t *testing.T, p profile.Profile, apiKey, token string, now time.Time) *providerproxy.Server {
	t.Helper()
	server, err := providerproxy.Start(context.Background(), providerproxy.ServerOptions{
		Profile: p,
		APIKey:  apiKey,
		Token:   token,
		Expires: now.Add(time.Minute),
		Now:     func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	return server
}

func closeTestServer(t *testing.T, server *providerproxy.Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func providerProfile(targetURL string) profile.Profile {
	return profile.Profile{
		Name:           "openai/dev",
		Kind:           profile.KindProviderProxy,
		CredentialName: "openai/dev",
		Provider:       "openai-compatible",
		TargetURL:      targetURL,
		AllowedPaths:   []string{"/chat/completions"},
		AllowedMethods: []string{http.MethodPost},
		LocalTokenTTL:  time.Minute,
		ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
	}
}
