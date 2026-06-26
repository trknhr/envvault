package local

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/trknhr/envvault/internal/audit"
	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/issuer"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
)

type ProfileResolver interface {
	Profile(name string) (profile.Profile, error)
}

type TalosDeriver interface {
	DeriveJWT(ctx context.Context, parentKey string, grant issuer.Grant) (issuer.Credential, error)
}

type Issuer struct {
	profiles ProfileResolver
	secrets  keyring.Store
	talos    TalosDeriver
	audit    audit.Recorder
}

func NewIssuer(profiles ProfileResolver, secrets keyring.Store, talos TalosDeriver) *Issuer {
	return &Issuer{profiles: profiles, secrets: secrets, talos: talos}
}

func NewIssuerWithAudit(profiles ProfileResolver, secrets keyring.Store, talos TalosDeriver, recorder audit.Recorder) *Issuer {
	return &Issuer{profiles: profiles, secrets: secrets, talos: talos, audit: recorder}
}

func (i *Issuer) Issue(ctx context.Context, requested issuer.Grant) (issuer.Credential, error) {
	p, err := i.profiles.Profile(requested.Profile)
	if err != nil {
		return issuer.Credential{}, err
	}

	grant, err := boundedGrant(p, requested)
	if err != nil {
		return issuer.Credential{}, err
	}

	parentKey, err := i.secrets.Get(ctx, keyring.ProfileParentKey(p.Name))
	if err != nil {
		return issuer.Credential{}, err
	}
	defer zero(parentKey)

	credential, err := i.talos.DeriveJWT(ctx, string(parentKey), grant)
	if err != nil {
		_ = i.recordCredentialIssued(ctx, p, grant, audit.ResultFailure, err)
		return issuer.Credential{}, err
	}
	if err := i.recordCredentialIssued(ctx, p, grant, audit.ResultSuccess, nil); err != nil {
		return issuer.Credential{}, err
	}
	return credential, nil
}

func (i *Issuer) recordCredentialIssued(ctx context.Context, p profile.Profile, grant issuer.Grant, result string, cause error) error {
	if i.audit == nil {
		return nil
	}
	event := audit.Event{
		Event:      audit.EventCredentialIssued,
		Profile:    p.Name,
		Kind:       string(p.Kind),
		Resource:   grant.Resource,
		Scopes:     append([]string(nil), grant.Scopes...),
		TTLSeconds: int64(grant.TTL.Seconds()),
		SessionID:  claimString(grant.Claims, "envvault_session_id"),
		ProjectID:  claimString(grant.Claims, "envvault_project_id"),
		Result:     result,
	}
	if code, ok := clerr.CodeOf(cause); ok {
		event.ErrorCode = code
	}
	return i.audit.Record(ctx, event)
}

func boundedGrant(p profile.Profile, requested issuer.Grant) (issuer.Grant, error) {
	switch p.Kind {
	case profile.KindProcess:
		return boundedProcessGrant(p, requested)
	case profile.KindBrowserSession:
		return boundedBrowserGrant(p, requested)
	default:
		return issuer.Grant{}, clerr.New(clerr.ProfileKindMismatch, p.Name)
	}
}

func boundedProcessGrant(p profile.Profile, requested issuer.Grant) (issuer.Grant, error) {
	return boundedGrantWithTTL(p, requested, p.TokenTTL, p.MaxTokenTTL, "process")
}

func boundedBrowserGrant(p profile.Profile, requested issuer.Grant) (issuer.Grant, error) {
	if requested.Claims["envvault_purpose"] != "browser-bootstrap" {
		return issuer.Grant{}, clerr.New(clerr.ConfigInvalid, "browser-session grant purpose must be browser-bootstrap")
	}
	return boundedGrantWithTTL(p, requested, p.BootstrapTokenTTL, p.BootstrapTokenTTL, "browser-bootstrap")
}

func boundedGrantWithTTL(p profile.Profile, requested issuer.Grant, defaultTTL, maxTTL time.Duration, defaultPurpose string) (issuer.Grant, error) {
	if requested.Resource != "" && requested.Resource != p.Resource {
		return issuer.Grant{}, clerr.New(clerr.ConfigInvalid, "grant resource must match profile resource")
	}

	scopes := requested.Scopes
	if len(scopes) == 0 {
		scopes = p.Scopes
	}
	if !p.AllowsScopes(scopes) {
		return issuer.Grant{}, clerr.New(clerr.ConfigInvalid, "grant scopes exceed profile scopes")
	}

	ttl := requested.TTL
	if ttl == 0 {
		ttl = defaultTTL
	}
	if ttl <= 0 {
		return issuer.Grant{}, clerr.New(clerr.ConfigInvalid, "grant ttl must be positive")
	}
	if ttl > maxTTL {
		return issuer.Grant{}, clerr.New(clerr.ConfigInvalid, "grant ttl exceeds profile max ttl")
	}

	claims, err := boundedClaims(p, requested.Claims, defaultPurpose)
	if err != nil {
		return issuer.Grant{}, err
	}

	return issuer.Grant{
		Profile:  p.Name,
		Resource: p.Resource,
		Scopes:   append([]string(nil), scopes...),
		TTL:      ttl,
		Claims:   claims,
	}, nil
}

func boundedClaims(p profile.Profile, requested map[string]any, defaultPurpose string) (map[string]any, error) {
	if err := validateClaimNames(requested); err != nil {
		return nil, err
	}
	if err := validateProfileClaimNames(p.Claims); err != nil {
		return nil, err
	}

	claims := cloneClaims(requested)
	for key, value := range p.Claims {
		claims[key] = value
	}
	if _, ok := claims["envvault_session_id"]; !ok {
		sessionID, err := newSessionID()
		if err != nil {
			return nil, err
		}
		claims["envvault_session_id"] = sessionID
	}
	claims["envvault_profile"] = p.Name
	claims["envvault_resource"] = p.Resource
	claims["envvault_purpose"] = defaultPurpose
	return claims, nil
}

func validateClaimNames(claims map[string]any) error {
	for claim := range claims {
		if reservedJWTClaims[strings.ToLower(strings.TrimSpace(claim))] {
			return clerr.New(clerr.ConfigInvalid, "reserved jwt claim is not allowed in custom claims")
		}
	}
	return nil
}

func validateProfileClaimNames(claims map[string]string) error {
	for claim := range claims {
		if reservedJWTClaims[strings.ToLower(strings.TrimSpace(claim))] {
			return clerr.New(clerr.ConfigInvalid, "reserved jwt claim is not allowed in profile claims")
		}
	}
	return nil
}

var reservedJWTClaims = map[string]bool{
	"iss": true,
	"sub": true,
	"aud": true,
	"exp": true,
	"nbf": true,
	"iat": true,
	"jti": true,
}

func cloneClaims(in map[string]any) map[string]any {
	out := make(map[string]any, len(in)+4)
	for key, value := range in {
		out[key] = value
	}
	return out
}

func claimString(claims map[string]any, key string) string {
	value, ok := claims[key]
	if !ok {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return text
}

func newSessionID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", clerr.Wrap(clerr.IssueFailed, "generate session id", err)
	}
	return "hex:" + hex.EncodeToString(bytes[:]), nil
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
