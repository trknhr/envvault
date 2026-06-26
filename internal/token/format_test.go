package token_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/issuer"
	"github.com/trknhr/envvault/internal/token"
)

func TestWriteRawToken(t *testing.T) {
	var stdout bytes.Buffer
	credential := issuer.Credential{
		AccessToken: "leased-jwt",
		TokenType:   "Bearer",
		ExpiresAt:   time.Date(2026, 6, 22, 12, 10, 0, 0, time.UTC),
		Scopes:      []string{"repository:read"},
	}

	if err := token.Write(&stdout, token.Output{
		Format:     token.FormatRaw,
		Credential: credential,
		Profile:    "backend-a/dev",
		Resource:   "https://api.dev.example.com",
		Now:        time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	if got, want := stdout.String(), "leased-jwt\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestWriteJSONToken(t *testing.T) {
	var stdout bytes.Buffer
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)

	err := token.Write(&stdout, token.Output{
		Format: token.FormatJSON,
		Credential: issuer.Credential{
			AccessToken: "leased-jwt",
			TokenType:   "Bearer",
			ExpiresAt:   now.Add(10 * time.Minute),
			Scopes:      []string{"repository:read", "issue:read"},
		},
		Profile:  "backend-a/dev",
		Resource: "https://api.dev.example.com",
		Now:      now,
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body=%s", err, stdout.String())
	}
	if got["access_token"] != "leased-jwt" {
		t.Fatalf("access_token = %v", got["access_token"])
	}
	if got["token_type"] != "Bearer" {
		t.Fatalf("token_type = %v", got["token_type"])
	}
	if got["expires_at"] != "2026-06-22T12:10:00Z" {
		t.Fatalf("expires_at = %v", got["expires_at"])
	}
	if got["expires_in"] != float64(600) {
		t.Fatalf("expires_in = %v", got["expires_in"])
	}
	if got["profile"] != "backend-a/dev" {
		t.Fatalf("profile = %v", got["profile"])
	}
	if got["resource"] != "https://api.dev.example.com" {
		t.Fatalf("resource = %v", got["resource"])
	}
}

func TestWriteRejectsUnknownFormat(t *testing.T) {
	err := token.Write(new(bytes.Buffer), token.Output{Format: token.Format("yaml")})
	if err == nil {
		t.Fatal("Write() error = nil, want error")
	}
}
