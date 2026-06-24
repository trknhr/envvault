package talosruntime_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/issuer"
	"github.com/trknhr/credlease/internal/issuer/talos"
	"github.com/trknhr/credlease/internal/issuer/talosruntime"
	runtimetalos "github.com/trknhr/credlease/internal/runtime/talos"
)

func TestClientDerivesJWTThroughRuntimeAndStopsBeforeReturning(t *testing.T) {
	runtime := &fakeRuntime{}
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if runtime.stops != 0 {
			t.Fatal("runtime stopped before Talos request completed")
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v2alpha1/admin/apiKeys:derive" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":{"token":"leased-jwt"}}`))
	}))
	defer server.Close()
	runtime.endpoint = runtimetalos.Endpoint{URL: server.URL, Address: "127.0.0.1:1"}

	client := talosruntime.Client{Runtime: runtime, HTTP: server.Client()}
	credential, err := client.DeriveJWT(context.Background(), "parent-secret", issuer.Grant{
		Profile: "backend-a/dev",
		Scopes:  []string{"repository:read"},
		TTL:     10 * time.Minute,
		Claims: map[string]any{
			"credlease_profile": "backend-a/dev",
		},
	})
	if err != nil {
		t.Fatalf("DeriveJWT() error = %v", err)
	}
	if credential.AccessToken != "leased-jwt" {
		t.Fatalf("AccessToken = %q", credential.AccessToken)
	}
	if runtime.starts != 1 || runtime.stops != 1 {
		t.Fatalf("starts/stops = %d/%d, want 1/1", runtime.starts, runtime.stops)
	}
	if got["credential"] != "parent-secret" {
		t.Fatalf("credential = %v", got["credential"])
	}
}

func TestClientRequiresRuntime(t *testing.T) {
	client := talosruntime.Client{}
	_, err := client.DeriveJWT(context.Background(), "parent-secret", issuer.Grant{
		Profile: "backend-a/dev",
		Scopes:  []string{"repository:read"},
		TTL:     10 * time.Minute,
		Claims:  map[string]any{"credlease_profile": "backend-a/dev"},
	})
	if err == nil {
		t.Fatal("DeriveJWT() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.RuntimeUnavailable {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.RuntimeUnavailable)
	}
}

func TestClientStopsRuntimeWhenDeriveFailsWithoutLeakingResponseBody(t *testing.T) {
	runtime := &fakeRuntime{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "parent-secret leaked body", http.StatusInternalServerError)
	}))
	defer server.Close()
	runtime.endpoint = runtimetalos.Endpoint{URL: server.URL, Address: "127.0.0.1:1"}

	client := talosruntime.Client{Runtime: runtime, HTTP: server.Client()}
	_, err := client.DeriveJWT(context.Background(), "parent-secret", issuer.Grant{
		Profile: "backend-a/dev",
		Scopes:  []string{"repository:read"},
		TTL:     10 * time.Minute,
		Claims:  map[string]any{"credlease_profile": "backend-a/dev"},
	})
	if err == nil {
		t.Fatal("DeriveJWT() error = nil, want error")
	}
	if runtime.starts != 1 || runtime.stops != 1 {
		t.Fatalf("starts/stops = %d/%d, want 1/1", runtime.starts, runtime.stops)
	}
	if strings.Contains(err.Error(), "parent-secret") || strings.Contains(err.Error(), "leaked body") {
		t.Fatalf("error leaked secret/body: %q", err.Error())
	}
	if code, _ := clerr.CodeOf(err); code != clerr.IssueFailed {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.IssueFailed)
	}
}

func TestClientFailsClosedWhenRuntimeStopFailsAfterDerive(t *testing.T) {
	runtime := &fakeRuntime{
		stopErr: clerr.New(clerr.CleanupFailed, "stop failed"),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":{"token":"leased-jwt"}}`))
	}))
	defer server.Close()
	runtime.endpoint = runtimetalos.Endpoint{URL: server.URL, Address: "127.0.0.1:1"}

	client := talosruntime.Client{Runtime: runtime, HTTP: server.Client()}
	credential, err := client.DeriveJWT(context.Background(), "parent-secret", issuer.Grant{
		Profile: "backend-a/dev",
		Scopes:  []string{"repository:read"},
		TTL:     10 * time.Minute,
		Claims:  map[string]any{"credlease_profile": "backend-a/dev"},
	})
	if err == nil {
		t.Fatal("DeriveJWT() error = nil, want cleanup error")
	}
	if credential.AccessToken != "" {
		t.Fatalf("AccessToken = %q, want empty on cleanup failure", credential.AccessToken)
	}
	if code, _ := clerr.CodeOf(err); code != clerr.CleanupFailed {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.CleanupFailed)
	}
	if runtime.stops != 1 {
		t.Fatalf("stops = %d, want 1", runtime.stops)
	}
}

func TestClientIssuesParentKeyAndFetchesJWKSWithRuntimeLifecycle(t *testing.T) {
	runtime := &fakeRuntime{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v2alpha1/admin/issuedApiKeys":
			_, _ = w.Write([]byte(`{"id":"key-id","secret":"parent-secret"}`))
		case "/v2alpha1/derivedKeys/jwks.json":
			_, _ = w.Write([]byte(`{"keys":[{"kid":"test-kid"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	runtime.endpoint = runtimetalos.Endpoint{URL: server.URL, Address: "127.0.0.1:1"}

	client := talosruntime.Client{Runtime: runtime, HTTP: server.Client()}
	parent, err := client.IssueParentKey(context.Background(), talos.ParentKeyRequest{
		Profile:        "backend-a/dev",
		InstallationID: "hex:install",
		Scopes:         []string{"repository:read"},
		TTL:            time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueParentKey() error = %v", err)
	}
	jwks, err := client.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}

	if parent.Secret != "parent-secret" {
		t.Fatalf("Secret = %q", parent.Secret)
	}
	if string(jwks) != `{"keys":[{"kid":"test-kid"}]}` {
		t.Fatalf("JWKS() = %s", jwks)
	}
	if runtime.starts != 2 || runtime.stops != 2 {
		t.Fatalf("starts/stops = %d/%d, want 2/2", runtime.starts, runtime.stops)
	}
}

type fakeRuntime struct {
	endpoint runtimetalos.Endpoint
	stopErr  error
	starts   int
	stops    int
}

func (r *fakeRuntime) Start(context.Context) (runtimetalos.Endpoint, error) {
	r.starts++
	return r.endpoint, nil
}

func (r *fakeRuntime) Stop(context.Context) error {
	r.stops++
	return r.stopErr
}
