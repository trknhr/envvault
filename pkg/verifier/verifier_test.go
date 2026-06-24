package verifier_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/credlease/pkg/verifier"
)

func TestBrowserBootstrapVerifierReturnsGrantForSessionServer(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	key := newTestRSAKey(t)
	token := signRS256(t, key, map[string]any{
		"iss":                          "credlease-local:test-install",
		"exp":                          now.Add(60 * time.Second).Unix(),
		"scope":                        "browser:session:create",
		"credlease_profile":            "admin-web/dev",
		"credlease_resource":           "https://admin.dev.example.com",
		"credlease_session_id":         "session-1",
		"credlease_purpose":            "browser-bootstrap",
		"non_credlease_application_id": "kept",
	})
	v := newVerifier(t, key, now, "https://admin.dev.example.com")
	bootstrap := verifier.BrowserBootstrapVerifier{
		Verifier: v,
		Scopes:   []string{"browser:session:create"},
	}

	grant, err := bootstrap.VerifyBootstrap(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyBootstrap() error = %v", err)
	}

	if grant.Profile != "admin-web/dev" {
		t.Fatalf("Profile = %q", grant.Profile)
	}
	if grant.Resource != "https://admin.dev.example.com" {
		t.Fatalf("Resource = %q", grant.Resource)
	}
	if grant.SessionID != "session-1" {
		t.Fatalf("SessionID = %q", grant.SessionID)
	}
	if grant.Purpose != "browser-bootstrap" {
		t.Fatalf("Purpose = %q", grant.Purpose)
	}
	if got, want := strings.Join(grant.Scopes, " "), "browser:session:create"; got != want {
		t.Fatalf("Scopes = %q, want %q", got, want)
	}
	if grant.ExpiresAt != now.Add(60*time.Second) {
		t.Fatalf("ExpiresAt = %s", grant.ExpiresAt)
	}
}

func TestVerifierAcceptsJWKSBackedJWTWithResourceScopeAndPurpose(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	key := newTestRSAKey(t)
	token := signRS256(t, key, map[string]any{
		"iss":                          "credlease-local:test-install",
		"sub":                          "local-user",
		"exp":                          now.Add(5 * time.Minute).Unix(),
		"nbf":                          now.Add(-time.Minute).Unix(),
		"scope":                        "repository:read issue:read",
		"credlease_profile":            "backend-a/dev",
		"credlease_resource":           "https://api.dev.example.com",
		"credlease_session_id":         "session-1",
		"credlease_purpose":            "process",
		"credlease_client":             "codex",
		"credlease_project_id":         "sha256:project",
		"non_credlease_application_id": "kept",
	})

	v := newVerifier(t, key, now, "https://api.dev.example.com")
	claims, err := v.Verify(context.Background(), token, verifier.Requirements{
		Scopes:  []string{"repository:read"},
		Purpose: "process",
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if claims.Issuer != "credlease-local:test-install" {
		t.Fatalf("Issuer = %q", claims.Issuer)
	}
	if claims.Subject != "local-user" {
		t.Fatalf("Subject = %q", claims.Subject)
	}
	if claims.Profile != "backend-a/dev" {
		t.Fatalf("Profile = %q", claims.Profile)
	}
	if claims.Resource != "https://api.dev.example.com" {
		t.Fatalf("Resource = %q", claims.Resource)
	}
	if claims.SessionID != "session-1" {
		t.Fatalf("SessionID = %q", claims.SessionID)
	}
	if claims.Purpose != "process" {
		t.Fatalf("Purpose = %q", claims.Purpose)
	}
	if got, want := strings.Join(claims.Scopes, " "), "repository:read issue:read"; got != want {
		t.Fatalf("Scopes = %q, want %q", got, want)
	}
	if claims.Raw["non_credlease_application_id"] != "kept" {
		t.Fatalf("Raw omitted application claim: %#v", claims.Raw)
	}
}

func TestVerifierAcceptsEd25519JWKSBackedJWT(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	token := signEdDSA(t, privateKey, map[string]any{
		"iss":                  "credlease-local:test-install",
		"exp":                  now.Add(5 * time.Minute).Unix(),
		"scope":                "repository:read",
		"credlease_profile":    "backend-a/dev",
		"credlease_resource":   "https://api.dev.example.com",
		"credlease_session_id": "session-1",
		"credlease_purpose":    "process",
	})
	v, err := verifier.New(verifier.Options{
		JWKS:          jwksForEd25519(t, publicKey),
		Issuer:        "credlease-local:test-install",
		Resource:      "https://api.dev.example.com",
		ClockSkew:     10 * time.Second,
		Now:           func() time.Time { return now },
		AllowedAlgs:   []string{"EdDSA"},
		RequireIssuer: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	claims, err := v.Verify(context.Background(), token, verifier.Requirements{
		Scopes:  []string{"repository:read"},
		Purpose: "process",
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims.Profile != "backend-a/dev" || claims.Resource != "https://api.dev.example.com" {
		t.Fatalf("claims = %#v", claims)
	}
}

func TestVerifierRejectsExpiredJWT(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	key := newTestRSAKey(t)
	token := signRS256(t, key, map[string]any{
		"iss":                "credlease-local:test-install",
		"exp":                now.Add(-30 * time.Second).Unix(),
		"credlease_resource": "https://api.dev.example.com",
		"credlease_purpose":  "process",
	})
	v := newVerifier(t, key, now, "https://api.dev.example.com")

	_, err := v.Verify(context.Background(), token, verifier.Requirements{Purpose: "process"})
	if err == nil {
		t.Fatal("Verify() error = nil, want expired-token error")
	}
	if !errors.Is(err, verifier.ErrTokenExpired) {
		t.Fatalf("Verify() error = %v, want ErrTokenExpired", err)
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("error leaked raw token: %q", err.Error())
	}
}

func TestVerifierRejectsResourceMismatch(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	key := newTestRSAKey(t)
	token := signRS256(t, key, map[string]any{
		"iss":                "credlease-local:test-install",
		"exp":                now.Add(time.Minute).Unix(),
		"credlease_resource": "https://api.dev.example.com",
		"credlease_purpose":  "process",
	})
	v := newVerifier(t, key, now, "https://other.dev.example.com")

	_, err := v.Verify(context.Background(), token, verifier.Requirements{Purpose: "process"})
	if err == nil {
		t.Fatal("Verify() error = nil, want resource mismatch")
	}
	if !errors.Is(err, verifier.ErrResourceMismatch) {
		t.Fatalf("Verify() error = %v, want ErrResourceMismatch", err)
	}
}

func TestVerifierRejectsMissingRequiredScope(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	key := newTestRSAKey(t)
	token := signRS256(t, key, map[string]any{
		"iss":                "credlease-local:test-install",
		"exp":                now.Add(time.Minute).Unix(),
		"scope":              "repository:read",
		"credlease_resource": "https://api.dev.example.com",
		"credlease_purpose":  "process",
	})
	v := newVerifier(t, key, now, "https://api.dev.example.com")

	_, err := v.Verify(context.Background(), token, verifier.Requirements{
		Scopes:  []string{"repository:write"},
		Purpose: "process",
	})
	if err == nil {
		t.Fatal("Verify() error = nil, want missing-scope error")
	}
	if !errors.Is(err, verifier.ErrScopeMissing) {
		t.Fatalf("Verify() error = %v, want ErrScopeMissing", err)
	}
}

func TestVerifierRejectsUnsignedAlgorithm(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	key := newTestRSAKey(t)
	header := base64.RawURLEncoding.EncodeToString(mustJSON(t, map[string]any{"alg": "none", "kid": "test-kid"}))
	payload := base64.RawURLEncoding.EncodeToString(mustJSON(t, map[string]any{
		"iss":                "credlease-local:test-install",
		"exp":                now.Add(time.Minute).Unix(),
		"credlease_resource": "https://api.dev.example.com",
		"credlease_purpose":  "process",
	}))
	token := header + "." + payload + "."
	v := newVerifier(t, key, now, "https://api.dev.example.com")

	_, err := v.Verify(context.Background(), token, verifier.Requirements{Purpose: "process"})
	if err == nil {
		t.Fatal("Verify() error = nil, want unsigned algorithm rejection")
	}
}

func newVerifier(t *testing.T, key *rsa.PrivateKey, now time.Time, resource string) *verifier.Verifier {
	t.Helper()
	v, err := verifier.New(verifier.Options{
		JWKS:          jwksForRSA(t, &key.PublicKey),
		Issuer:        "credlease-local:test-install",
		Resource:      resource,
		ClockSkew:     10 * time.Second,
		Now:           func() time.Time { return now },
		AllowedAlgs:   []string{"RS256"},
		RequireIssuer: true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return v
}

func newTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return key
}

func signRS256(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := mustJSON(t, map[string]any{"alg": "RS256", "kid": "test-kid", "typ": "JWT"})
	payload := mustJSON(t, claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15() error = %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func signEdDSA(t *testing.T, key ed25519.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := mustJSON(t, map[string]any{"alg": "EdDSA", "kid": "test-ed25519-kid", "typ": "JWT"})
	payload := mustJSON(t, claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(key, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func jwksForRSA(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	return mustJSON(t, map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": "test-kid",
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			},
		},
	})
}

func jwksForEd25519(t *testing.T, key ed25519.PublicKey) []byte {
	t.Helper()
	return mustJSON(t, map[string]any{
		"keys": []map[string]any{
			{
				"kty": "OKP",
				"kid": "test-ed25519-kid",
				"alg": "EdDSA",
				"use": "sig",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(key),
			},
		},
	})
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return raw
}
