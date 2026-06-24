package acceptance_test

import (
	"context"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	backendgo "github.com/trknhr/credlease/examples/backend-go"
)

func TestSampleBackendEnforcesProcessJWTTTLScopesResourcesAndJWKS(t *testing.T) {
	start := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	current := start
	key := newAcceptanceRSAKey(t)
	resourceA := "https://api-a.dev.example.com"
	resourceB := "https://api-b.dev.example.com"

	backendA := newAcceptanceProcessBackend(t, key, resourceA, func() time.Time { return current })
	backendB := newAcceptanceProcessBackend(t, key, resourceB, func() time.Time { return current })
	readOnlyToken := acceptanceProcessJWT(t, key, start, resourceA, "document:read", 5*time.Second)

	read := backendRequest(t, backendA, http.MethodGet, "/documents/read", readOnlyToken)
	if read.StatusCode != http.StatusOK {
		t.Fatalf("read status = %d, want 200; body=%s", read.StatusCode, responseBody(t, read))
	}
	if body := responseBody(t, read); !strings.Contains(body, `"operation":"read"`) || strings.Contains(body, readOnlyToken) {
		t.Fatalf("read body = %q, want read result without JWT", body)
	}

	write := backendRequest(t, backendA, http.MethodPost, "/documents/write", readOnlyToken)
	if write.StatusCode != http.StatusForbidden {
		t.Fatalf("write status = %d, want 403 for missing write scope; body=%s", write.StatusCode, responseBody(t, write))
	}
	if strings.Contains(responseBody(t, write), readOnlyToken) {
		t.Fatalf("write error leaked JWT: %q", responseBody(t, write))
	}

	wrongResource := backendRequest(t, backendB, http.MethodGet, "/documents/read", readOnlyToken)
	if wrongResource.StatusCode != http.StatusForbidden {
		t.Fatalf("resource mismatch status = %d, want 403; body=%s", wrongResource.StatusCode, responseBody(t, wrongResource))
	}

	current = start.Add(7 * time.Second)
	expired := backendRequest(t, backendA, http.MethodGet, "/documents/read", readOnlyToken)
	if expired.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired status = %d, want 401; body=%s", expired.StatusCode, responseBody(t, expired))
	}
	if strings.Contains(responseBody(t, expired), readOnlyToken) {
		t.Fatalf("expired error leaked JWT: %q", responseBody(t, expired))
	}
}

func newAcceptanceProcessBackend(t *testing.T, key *rsa.PrivateKey, resource string, now func() time.Time) *httptest.Server {
	t.Helper()
	backend, err := backendgo.New(backendgo.Config{
		JWKS:      acceptanceJWKSForRSA(t, &key.PublicKey),
		Issuer:    "credlease-local:test-install",
		Resource:  resource,
		ClockSkew: time.Second,
		Now:       now,
	})
	if err != nil {
		t.Fatalf("backendgo.New() error = %v", err)
	}
	server := httptest.NewServer(backend.Handler())
	t.Cleanup(server.Close)
	return server
}

func acceptanceProcessJWT(t *testing.T, key *rsa.PrivateKey, now time.Time, resource string, scopes string, ttl time.Duration) string {
	t.Helper()
	token, err := signAcceptanceRS256(key, map[string]any{
		"iss":                  "credlease-local:test-install",
		"sub":                  "local-user",
		"nbf":                  now.Add(-time.Second).Unix(),
		"exp":                  now.Add(ttl).Unix(),
		"scope":                scopes,
		"credlease_profile":    "backend-a/dev",
		"credlease_resource":   resource,
		"credlease_session_id": "session-process-1",
		"credlease_purpose":    "process",
	})
	if err != nil {
		t.Fatalf("signAcceptanceRS256() error = %v", err)
	}
	return token
}

func backendRequest(t *testing.T, server *httptest.Server, method, path, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, server.URL+path, nil)
	if err != nil {
		t.Fatalf("NewRequest(%s %s) error = %v", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("Do(%s %s) error = %v", method, path, err)
	}
	return resp
}

func responseBody(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("ReadAll(response body) error = %v", err)
	}
	return string(body)
}
