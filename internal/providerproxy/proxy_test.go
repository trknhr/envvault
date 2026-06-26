package providerproxy_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/projectbinding"
	"github.com/trknhr/envvault/internal/providerproxy"
)

func TestServerForwardsAllowedRequestWithProviderBearer(t *testing.T) {
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	var gotAuth, gotPath, gotQuery, gotBody string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	if gotAuth != "Bearer sk-real" {
		t.Fatalf("provider Authorization = %q, want provider bearer", gotAuth)
	}
	if gotPath != "/v1/chat/completions" {
		t.Fatalf("provider path = %q, want /v1/chat/completions", gotPath)
	}
	if gotQuery != "model=test" {
		t.Fatalf("provider query = %q, want model=test", gotQuery)
	}
	if gotBody != `{"messages":[]}` {
		t.Fatalf("provider body = %q", gotBody)
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
	var providerAuth string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerAuth = r.Header.Get("Authorization")
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
		t.Fatalf("token = %q, want local proxy token", localToken)
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
	if providerAuth != "Bearer sk-real" {
		t.Fatalf("provider Authorization = %q, want provider bearer", providerAuth)
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
		Provider:       "openai-compatible",
		TargetURL:      targetURL,
		AllowedPaths:   []string{"/chat/completions"},
		AllowedMethods: []string{http.MethodPost},
		LocalTokenTTL:  time.Minute,
		ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
	}
}
