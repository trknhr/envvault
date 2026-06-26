package verifier

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

var (
	ErrInvalidToken     = errors.New("envvault verifier: invalid token")
	ErrInvalidJWKS      = errors.New("envvault verifier: invalid jwks")
	ErrUnauthorized     = errors.New("envvault verifier: unauthorized token")
	ErrTokenExpired     = errors.New("envvault verifier: token expired")
	ErrTokenNotYetValid = errors.New("envvault verifier: token not yet valid")
	ErrIssuerMismatch   = errors.New("envvault verifier: issuer mismatch")
	ErrResourceMismatch = errors.New("envvault verifier: resource mismatch")
	ErrPurposeMismatch  = errors.New("envvault verifier: purpose mismatch")
	ErrScopeMissing     = errors.New("envvault verifier: required scope missing")
)

type Options struct {
	JWKS          []byte
	Issuer        string
	Resource      string
	ClockSkew     time.Duration
	Now           func() time.Time
	AllowedAlgs   []string
	RequireIssuer bool
}

type Requirements struct {
	Scopes  []string
	Purpose string
}

type Claims struct {
	Issuer    string
	Subject   string
	Profile   string
	Resource  string
	SessionID string
	Purpose   string
	Scopes    []string
	ExpiresAt time.Time
	NotBefore time.Time
	Raw       map[string]any
}

type Verifier struct {
	keys          map[string]jwk
	issuer        string
	resource      string
	clockSkew     time.Duration
	now           func() time.Time
	allowedAlgs   map[string]struct{}
	requireIssuer bool
}

type jwk struct {
	keyID string
	alg   string
	rsa   *rsa.PublicKey
	eddsa ed25519.PublicKey
}

func New(options Options) (*Verifier, error) {
	keys, err := parseJWKS(options.JWKS)
	if err != nil {
		return nil, err
	}
	allowedAlgs := map[string]struct{}{}
	if len(options.AllowedAlgs) == 0 {
		allowedAlgs["RS256"] = struct{}{}
		allowedAlgs["EdDSA"] = struct{}{}
	} else {
		for _, alg := range options.AllowedAlgs {
			if alg != "" {
				allowedAlgs[alg] = struct{}{}
			}
		}
	}
	if len(allowedAlgs) == 0 {
		return nil, fmt.Errorf("%w: allowed algorithms are required", ErrInvalidJWKS)
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Verifier{
		keys:          keys,
		issuer:        options.Issuer,
		resource:      options.Resource,
		clockSkew:     options.ClockSkew,
		now:           now,
		allowedAlgs:   allowedAlgs,
		requireIssuer: options.RequireIssuer,
	}, nil
}

func (v *Verifier) Verify(ctx context.Context, token string, requirements Requirements) (Claims, error) {
	if err := ctx.Err(); err != nil {
		return Claims{}, err
	}

	header, payload, signingInput, signature, err := splitJWT(token)
	if err != nil {
		return Claims{}, err
	}
	key, err := v.keyForHeader(header)
	if err != nil {
		return Claims{}, err
	}
	if err := verifySignature(key, signingInput, signature, header.Algorithm); err != nil {
		return Claims{}, err
	}

	claims, err := parseClaims(payload)
	if err != nil {
		return Claims{}, err
	}
	if err := v.validateClaims(claims, requirements); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

func splitJWT(token string) (jwtHeader, []byte, string, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return jwtHeader{}, nil, "", nil, ErrInvalidToken
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return jwtHeader{}, nil, "", nil, ErrInvalidToken
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return jwtHeader{}, nil, "", nil, ErrInvalidToken
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return jwtHeader{}, nil, "", nil, ErrInvalidToken
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return jwtHeader{}, nil, "", nil, ErrInvalidToken
	}
	return header, payloadBytes, parts[0] + "." + parts[1], signature, nil
}

func (v *Verifier) keyForHeader(header jwtHeader) (jwk, error) {
	if header.Algorithm == "" || header.KeyID == "" {
		return jwk{}, ErrInvalidToken
	}
	if _, ok := v.allowedAlgs[header.Algorithm]; !ok {
		return jwk{}, ErrUnauthorized
	}
	key, ok := v.keys[header.KeyID]
	if !ok {
		return jwk{}, ErrUnauthorized
	}
	if key.alg != "" && key.alg != header.Algorithm {
		return jwk{}, ErrUnauthorized
	}
	return key, nil
}

func verifySignature(key jwk, signingInput string, signature []byte, alg string) error {
	switch alg {
	case "RS256":
		if key.rsa == nil {
			return ErrUnauthorized
		}
		sum := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(key.rsa, crypto.SHA256, sum[:], signature); err != nil {
			return ErrUnauthorized
		}
		return nil
	case "EdDSA":
		if len(key.eddsa) != ed25519.PublicKeySize {
			return ErrUnauthorized
		}
		if !ed25519.Verify(key.eddsa, []byte(signingInput), signature) {
			return ErrUnauthorized
		}
		return nil
	default:
		return ErrUnauthorized
	}
}

func parseClaims(payload []byte) (Claims, error) {
	var raw map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.UseNumber()
	if err := decoder.Decode(&raw); err != nil {
		return Claims{}, ErrInvalidToken
	}

	exp, err := numericDate(raw["exp"])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	nbf, err := optionalNumericDate(raw["nbf"])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	claims := Claims{
		Issuer:    stringClaim(raw["iss"]),
		Subject:   stringClaim(raw["sub"]),
		Profile:   stringClaim(raw["envvault_profile"]),
		Resource:  stringClaim(raw["envvault_resource"]),
		SessionID: stringClaim(raw["envvault_session_id"]),
		Purpose:   stringClaim(raw["envvault_purpose"]),
		Scopes:    scopeClaims(raw),
		ExpiresAt: exp,
		NotBefore: nbf,
		Raw:       raw,
	}
	return claims, nil
}

func (v *Verifier) validateClaims(claims Claims, requirements Requirements) error {
	now := v.now()
	if claims.ExpiresAt.IsZero() || !claims.ExpiresAt.After(now.Add(-v.clockSkew)) {
		return ErrTokenExpired
	}
	if !claims.NotBefore.IsZero() && claims.NotBefore.After(now.Add(v.clockSkew)) {
		return ErrTokenNotYetValid
	}
	if v.requireIssuer && (v.issuer == "" || claims.Issuer != v.issuer) {
		return ErrIssuerMismatch
	}
	if v.resource != "" && claims.Resource != v.resource {
		return ErrResourceMismatch
	}
	if requirements.Purpose != "" && claims.Purpose != requirements.Purpose {
		return ErrPurposeMismatch
	}
	if !containsAll(claims.Scopes, requirements.Scopes) {
		return ErrScopeMissing
	}
	return nil
}

func parseJWKS(body []byte) (map[string]jwk, error) {
	var parsed struct {
		Keys []struct {
			KeyType string `json:"kty"`
			KeyID   string `json:"kid"`
			Use     string `json:"use"`
			Alg     string `json:"alg"`
			Curve   string `json:"crv"`
			N       string `json:"n"`
			E       string `json:"e"`
			X       string `json:"x"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("%w: parse jwks", ErrInvalidJWKS)
	}
	if len(parsed.Keys) == 0 {
		return nil, fmt.Errorf("%w: keys are required", ErrInvalidJWKS)
	}
	keys := map[string]jwk{}
	for _, raw := range parsed.Keys {
		if raw.KeyID == "" || raw.Use == "enc" {
			continue
		}
		switch raw.KeyType {
		case "RSA":
			key, err := parseRSAJWK(raw.N, raw.E)
			if err != nil {
				return nil, err
			}
			keys[raw.KeyID] = jwk{keyID: raw.KeyID, alg: raw.Alg, rsa: key}
		case "OKP":
			key, err := parseEd25519JWK(raw.Curve, raw.X)
			if err != nil {
				return nil, err
			}
			keys[raw.KeyID] = jwk{keyID: raw.KeyID, alg: raw.Alg, eddsa: key}
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no supported signing keys", ErrInvalidJWKS)
	}
	return keys, nil
}

func parseRSAJWK(nRaw, eRaw string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nRaw)
	if err != nil || len(nBytes) == 0 {
		return nil, fmt.Errorf("%w: invalid rsa modulus", ErrInvalidJWKS)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eRaw)
	if err != nil || len(eBytes) == 0 {
		return nil, fmt.Errorf("%w: invalid rsa exponent", ErrInvalidJWKS)
	}
	exponent := int(new(big.Int).SetBytes(eBytes).Int64())
	if exponent < 3 {
		return nil, fmt.Errorf("%w: invalid rsa exponent", ErrInvalidJWKS)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: exponent}, nil
}

func parseEd25519JWK(curve, xRaw string) (ed25519.PublicKey, error) {
	if curve != "Ed25519" {
		return nil, fmt.Errorf("%w: unsupported okp curve", ErrInvalidJWKS)
	}
	x, err := base64.RawURLEncoding.DecodeString(xRaw)
	if err != nil || len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid ed25519 public key", ErrInvalidJWKS)
	}
	key := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(key, x)
	return key, nil
}

func numericDate(value any) (time.Time, error) {
	if value == nil {
		return time.Time{}, ErrInvalidToken
	}
	return optionalNumericDate(value)
}

func optionalNumericDate(value any) (time.Time, error) {
	if value == nil {
		return time.Time{}, nil
	}
	switch v := value.(type) {
	case json.Number:
		seconds, err := v.Int64()
		if err != nil {
			return time.Time{}, err
		}
		return time.Unix(seconds, 0).UTC(), nil
	case float64:
		return time.Unix(int64(v), 0).UTC(), nil
	default:
		return time.Time{}, ErrInvalidToken
	}
}

func stringClaim(value any) string {
	if str, ok := value.(string); ok {
		return str
	}
	return ""
}

func scopeClaims(raw map[string]any) []string {
	if scopes := scopesFromValue(raw["scope"]); len(scopes) > 0 {
		return scopes
	}
	return scopesFromValue(raw["scp"])
}

func scopesFromValue(value any) []string {
	switch v := value.(type) {
	case string:
		return strings.Fields(v)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok && str != "" {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}

func containsAll(have, want []string) bool {
	set := map[string]struct{}{}
	for _, scope := range have {
		set[scope] = struct{}{}
	}
	for _, scope := range want {
		if _, ok := set[scope]; !ok {
			return false
		}
	}
	return true
}
