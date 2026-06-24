package talos_test

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
)

func TestIssueParentKeyPostsTalosContract(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v2alpha1/admin/issuedApiKeys" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("Content-Type = %q", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"key-id","secret":"parent-secret"}`))
	}))
	defer server.Close()

	client := talos.NewClient(server.URL, server.Client())
	parent, err := client.IssueParentKey(context.Background(), talos.ParentKeyRequest{
		Profile:        "backend-a/dev",
		InstallationID: "01JTESTINSTALL",
		Scopes:         []string{"repository:read", "issue:read"},
		TTL:            2160 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueParentKey() error = %v", err)
	}

	if parent.Secret != "parent-secret" {
		t.Fatalf("Secret = %q", parent.Secret)
	}
	if got["name"] != "credlease:backend-a/dev" {
		t.Fatalf("name = %v", got["name"])
	}
	if got["actor_id"] != "credlease-local:01JTESTINSTALL" {
		t.Fatalf("actor_id = %v", got["actor_id"])
	}
	if got["ttl"] != "2160h0m0s" {
		t.Fatalf("ttl = %v", got["ttl"])
	}
	scopes := got["scopes"].([]any)
	if len(scopes) != 2 || scopes[0] != "repository:read" || scopes[1] != "issue:read" {
		t.Fatalf("scopes = %#v", scopes)
	}
	metadata := got["metadata"].(map[string]any)
	if metadata["credlease_profile"] != "backend-a/dev" {
		t.Fatalf("metadata = %#v", metadata)
	}
}

func TestDeriveJWTPostsExplicitScopesAndCustomClaims(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	client := talos.NewClient(server.URL, server.Client())
	credential, err := client.DeriveJWT(context.Background(), "parent-secret", issuer.Grant{
		Profile:  "backend-a/dev",
		Resource: "https://api.dev.example.com",
		Scopes:   []string{"repository:read"},
		TTL:      10 * time.Minute,
		Claims: map[string]any{
			"credlease_profile":    "backend-a/dev",
			"credlease_resource":   "https://api.dev.example.com",
			"credlease_session_id": "01JSESSION",
			"credlease_purpose":    "process",
		},
	})
	if err != nil {
		t.Fatalf("DeriveJWT() error = %v", err)
	}

	if credential.AccessToken != "leased-jwt" {
		t.Fatalf("AccessToken = %q", credential.AccessToken)
	}
	if credential.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q", credential.TokenType)
	}
	if got["credential"] != "parent-secret" {
		t.Fatalf("credential = %v", got["credential"])
	}
	if got["algorithm"] != "TOKEN_ALGORITHM_JWT" {
		t.Fatalf("algorithm = %v", got["algorithm"])
	}
	if got["ttl"] != "10m0s" {
		t.Fatalf("ttl = %v", got["ttl"])
	}
	scopes := got["scopes"].([]any)
	if len(scopes) != 1 || scopes[0] != "repository:read" {
		t.Fatalf("scopes = %#v", scopes)
	}
	claims := got["custom_claims"].(map[string]any)
	if claims["credlease_resource"] != "https://api.dev.example.com" {
		t.Fatalf("custom_claims = %#v", claims)
	}
}

func TestDeriveJWTRequiresExplicitScopesBeforeRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer server.Close()

	client := talos.NewClient(server.URL, server.Client())
	_, err := client.DeriveJWT(context.Background(), "parent-secret", issuer.Grant{
		Profile: "backend-a/dev",
		TTL:     10 * time.Minute,
	})
	if err == nil {
		t.Fatal("DeriveJWT() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ConfigInvalid {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ConfigInvalid)
	}
	if requests != 0 {
		t.Fatalf("requests = %d, want 0", requests)
	}
}

func TestDeriveJWTRejectsReservedCustomClaimBeforeRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer server.Close()

	client := talos.NewClient(server.URL, server.Client())
	_, err := client.DeriveJWT(context.Background(), "parent-secret", issuer.Grant{
		Profile: "backend-a/dev",
		Scopes:  []string{"repository:read"},
		TTL:     10 * time.Minute,
		Claims: map[string]any{
			"exp": "2026-06-22T12:00:00Z",
		},
	})
	if err == nil {
		t.Fatal("DeriveJWT() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ConfigInvalid {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ConfigInvalid)
	}
	if requests != 0 {
		t.Fatalf("requests = %d, want 0", requests)
	}
}

func TestTalosHTTPErrorDoesNotEchoSecretOrBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "parent-secret leaked body", http.StatusInternalServerError)
	}))
	defer server.Close()

	client := talos.NewClient(server.URL, server.Client())
	_, err := client.DeriveJWT(context.Background(), "parent-secret", issuer.Grant{
		Profile: "backend-a/dev",
		Scopes:  []string{"repository:read"},
		TTL:     10 * time.Minute,
		Claims:  map[string]any{"credlease_profile": "backend-a/dev"},
	})
	if err == nil {
		t.Fatal("DeriveJWT() error = nil, want error")
	}
	msg := err.Error()
	if strings.Contains(msg, "parent-secret") || strings.Contains(msg, "leaked body") {
		t.Fatalf("error leaked secret/body: %q", msg)
	}
	if code, _ := clerr.CodeOf(err); code != clerr.IssueFailed {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.IssueFailed)
	}
}

func TestJWKSFetchesPublicKeySet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v2alpha1/derivedKeys/jwks.json" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[{"kid":"test-kid"}]}`))
	}))
	defer server.Close()

	client := talos.NewClient(server.URL, server.Client())
	jwks, err := client.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	if string(jwks) != `{"keys":[{"kid":"test-kid"}]}` {
		t.Fatalf("JWKS() = %s", jwks)
	}
}
