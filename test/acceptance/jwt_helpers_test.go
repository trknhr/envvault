package acceptance_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/issuer"
)

type signingAcceptanceIssuer struct {
	key    *rsa.PrivateKey
	issuer string
	now    time.Time
	token  string
	grants []issuer.Grant
}

func (s *signingAcceptanceIssuer) Issue(ctx context.Context, grant issuer.Grant) (issuer.Credential, error) {
	if err := ctx.Err(); err != nil {
		return issuer.Credential{}, err
	}
	s.grants = append(s.grants, grant)

	claims := make(map[string]any, len(grant.Claims)+4)
	for key, value := range grant.Claims {
		claims[key] = value
	}
	claims["iss"] = s.issuer
	claims["nbf"] = s.now.Add(-time.Second).Unix()
	claims["exp"] = s.now.Add(grant.TTL).Unix()
	claims["scope"] = strings.Join(grant.Scopes, " ")

	token, err := signAcceptanceRS256(s.key, claims)
	if err != nil {
		return issuer.Credential{}, err
	}
	s.token = token
	return issuer.Credential{
		AccessToken: s.token,
		TokenType:   "Bearer",
		ExpiresAt:   s.now.Add(grant.TTL),
		Scopes:      append([]string(nil), grant.Scopes...),
	}, nil
}

func newAcceptanceRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return key
}

func signAcceptanceRS256(key *rsa.PrivateKey, claims map[string]any) (string, error) {
	header, err := acceptanceJSON(map[string]any{"alg": "RS256", "kid": "acceptance-test-kid", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := acceptanceJSON(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign acceptance JWT: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func acceptanceJWKSForRSA(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	return acceptanceMustJSON(t, map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": "acceptance-test-kid",
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			},
		},
	})
}

func acceptanceMustJSON(t interface {
	Helper()
	Fatalf(string, ...any)
}, value any) []byte {
	t.Helper()
	raw, err := acceptanceJSON(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return raw
}

func acceptanceJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal acceptance JSON: %w", err)
	}
	return raw, nil
}
