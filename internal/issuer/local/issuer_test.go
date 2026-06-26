package local_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/audit"
	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/issuer"
	"github.com/trknhr/envvault/internal/issuer/local"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
)

func TestIssuerLoadsParentKeyAndDerivesProfileBoundToken(t *testing.T) {
	ctx := context.Background()
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.ProfileParentKey("backend-a/dev"), []byte("parent-secret")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	deriver := &fakeDeriver{}
	service := local.NewIssuer(fakeProfiles(), secrets, deriver)

	credential, err := service.Issue(ctx, issuer.Grant{
		Profile: "backend-a/dev",
		Scopes:  []string{"repository:read"},
		TTL:     5 * time.Minute,
		Claims:  map[string]any{"envvault_client": "codex"},
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if credential.AccessToken != "leased-jwt" {
		t.Fatalf("AccessToken = %q", credential.AccessToken)
	}
	if deriver.parentKey != "parent-secret" {
		t.Fatalf("parentKey = %q", deriver.parentKey)
	}
	if deriver.grant.Profile != "backend-a/dev" {
		t.Fatalf("grant profile = %q", deriver.grant.Profile)
	}
	if deriver.grant.Resource != "https://api.dev.example.com" {
		t.Fatalf("grant resource = %q", deriver.grant.Resource)
	}
	if deriver.grant.TTL != 5*time.Minute {
		t.Fatalf("grant ttl = %s", deriver.grant.TTL)
	}
	if len(deriver.grant.Scopes) != 1 || deriver.grant.Scopes[0] != "repository:read" {
		t.Fatalf("grant scopes = %#v", deriver.grant.Scopes)
	}
	if deriver.grant.Claims["environment"] != "dev" {
		t.Fatalf("profile claim missing: %#v", deriver.grant.Claims)
	}
	if deriver.grant.Claims["envvault_client"] != "codex" {
		t.Fatalf("request claim missing: %#v", deriver.grant.Claims)
	}
}

func TestIssuerDefaultsToProfileScopesAndTTL(t *testing.T) {
	ctx := context.Background()
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.ProfileParentKey("backend-a/dev"), []byte("parent-secret")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	deriver := &fakeDeriver{}
	service := local.NewIssuer(fakeProfiles(), secrets, deriver)

	_, err := service.Issue(ctx, issuer.Grant{Profile: "backend-a/dev"})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if deriver.grant.TTL != 10*time.Minute {
		t.Fatalf("grant ttl = %s, want 10m", deriver.grant.TTL)
	}
	if len(deriver.grant.Scopes) != 2 {
		t.Fatalf("grant scopes = %#v, want profile scopes", deriver.grant.Scopes)
	}
}

func TestIssuerKeepsEnvVaultBindingClaimsAuthoritative(t *testing.T) {
	ctx := context.Background()
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.ProfileParentKey("backend-a/dev"), []byte("parent-secret")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	profiles := fakeProfiles()
	p := profiles["backend-a/dev"]
	p.Claims = map[string]string{
		"envvault_profile":  "profile-claim",
		"envvault_resource": "https://profile-claim.example.com",
		"envvault_purpose":  "profile-purpose",
		"environment":       "dev",
	}
	profiles["backend-a/dev"] = p
	deriver := &fakeDeriver{}
	service := local.NewIssuer(profiles, secrets, deriver)

	_, err := service.Issue(ctx, issuer.Grant{
		Profile: "backend-a/dev",
		Scopes:  []string{"repository:read"},
		TTL:     5 * time.Minute,
		Claims: map[string]any{
			"envvault_profile":  "request-claim",
			"envvault_resource": "https://request-claim.example.com",
			"envvault_purpose":  "request-purpose",
		},
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	for key, want := range map[string]any{
		"envvault_profile":  "backend-a/dev",
		"envvault_resource": "https://api.dev.example.com",
		"envvault_purpose":  "process",
		"environment":       "dev",
	} {
		if got := deriver.grant.Claims[key]; got != want {
			t.Fatalf("grant.Claims[%s] = %#v, want %#v", key, got, want)
		}
	}
}

func TestIssuerRejectsScopeTTLAndResourceEscalationBeforeKeyring(t *testing.T) {
	tests := []struct {
		name  string
		grant issuer.Grant
	}{
		{
			name:  "scope escalation",
			grant: issuer.Grant{Profile: "backend-a/dev", Scopes: []string{"admin:write"}},
		},
		{
			name:  "ttl escalation",
			grant: issuer.Grant{Profile: "backend-a/dev", TTL: time.Hour},
		},
		{
			name:  "resource override",
			grant: issuer.Grant{Profile: "backend-a/dev", Resource: "https://evil.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deriver := &fakeDeriver{}
			service := local.NewIssuer(fakeProfiles(), panicStore{}, deriver)

			_, err := service.Issue(context.Background(), tt.grant)
			if err == nil {
				t.Fatal("Issue() error = nil, want error")
			}
			if code, _ := clerr.CodeOf(err); code != clerr.ConfigInvalid {
				t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ConfigInvalid)
			}
			if deriver.called {
				t.Fatal("deriver was called")
			}
		})
	}
}

func TestIssuerRejectsReservedJWTClaimsBeforeKeyring(t *testing.T) {
	tests := []struct {
		name     string
		profiles fakeProfileResolver
		grant    issuer.Grant
	}{
		{
			name:     "requested claim",
			profiles: fakeProfiles(),
			grant: issuer.Grant{
				Profile: "backend-a/dev",
				Claims:  map[string]any{"exp": "2026-06-22T12:00:00Z"},
			},
		},
		{
			name: "profile claim",
			profiles: func() fakeProfileResolver {
				profiles := fakeProfiles()
				p := profiles["backend-a/dev"]
				p.Claims = map[string]string{"nbf": "2026-06-22T12:00:00Z"}
				profiles["backend-a/dev"] = p
				return profiles
			}(),
			grant: issuer.Grant{Profile: "backend-a/dev"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deriver := &fakeDeriver{}
			service := local.NewIssuer(tt.profiles, panicStore{}, deriver)

			_, err := service.Issue(context.Background(), tt.grant)
			if err == nil {
				t.Fatal("Issue() error = nil, want error")
			}
			if code, _ := clerr.CodeOf(err); code != clerr.ConfigInvalid {
				t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ConfigInvalid)
			}
			if deriver.called {
				t.Fatal("deriver was called")
			}
		})
	}
}

func TestIssuerFailsClosedWhenParentKeyMissing(t *testing.T) {
	deriver := &fakeDeriver{}
	service := local.NewIssuer(fakeProfiles(), keyring.NewMemoryStore(), deriver)

	_, err := service.Issue(context.Background(), issuer.Grant{Profile: "backend-a/dev"})
	if err == nil {
		t.Fatal("Issue() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ParentKeyMissing {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ParentKeyMissing)
	}
	if deriver.called {
		t.Fatal("deriver was called")
	}
}

func TestIssuerPropagatesKeyringUnavailable(t *testing.T) {
	deriver := &fakeDeriver{}
	service := local.NewIssuer(fakeProfiles(), keyring.UnavailableStore{}, deriver)

	_, err := service.Issue(context.Background(), issuer.Grant{Profile: "backend-a/dev"})
	if err == nil {
		t.Fatal("Issue() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.KeyringUnavailable {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.KeyringUnavailable)
	}
	if deriver.called {
		t.Fatal("deriver was called")
	}
}

func TestIssuerRejectsBrowserProfileForProcessToken(t *testing.T) {
	service := local.NewIssuer(fakeProfiles(), keyring.NewMemoryStore(), &fakeDeriver{})

	_, err := service.Issue(context.Background(), issuer.Grant{Profile: "admin-web/dev"})
	if err == nil {
		t.Fatal("Issue() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ConfigInvalid {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ConfigInvalid)
	}
}

func TestIssuerDerivesBrowserBootstrapToken(t *testing.T) {
	ctx := context.Background()
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.ProfileParentKey("admin-web/dev"), []byte("browser-parent-secret")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	deriver := &fakeDeriver{}
	service := local.NewIssuer(fakeProfiles(), secrets, deriver)

	credential, err := service.Issue(ctx, issuer.Grant{
		Profile: "admin-web/dev",
		Scopes:  []string{"browser:session:create"},
		TTL:     45 * time.Second,
		Claims: map[string]any{
			"envvault_client":  "envvault-cli",
			"envvault_purpose": "browser-bootstrap",
		},
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if credential.AccessToken != "leased-jwt" {
		t.Fatalf("AccessToken = %q", credential.AccessToken)
	}
	if deriver.parentKey != "browser-parent-secret" {
		t.Fatalf("parentKey = %q", deriver.parentKey)
	}
	if deriver.grant.Profile != "admin-web/dev" {
		t.Fatalf("grant profile = %q", deriver.grant.Profile)
	}
	if deriver.grant.Resource != "https://admin.dev.example.com" {
		t.Fatalf("grant resource = %q", deriver.grant.Resource)
	}
	if deriver.grant.TTL != 45*time.Second {
		t.Fatalf("grant ttl = %s", deriver.grant.TTL)
	}
	if len(deriver.grant.Scopes) != 1 || deriver.grant.Scopes[0] != "browser:session:create" {
		t.Fatalf("grant scopes = %#v", deriver.grant.Scopes)
	}
	if deriver.grant.Claims["envvault_purpose"] != "browser-bootstrap" {
		t.Fatalf("claims = %#v", deriver.grant.Claims)
	}
	if deriver.grant.Claims["envvault_resource"] != "https://admin.dev.example.com" {
		t.Fatalf("claims = %#v", deriver.grant.Claims)
	}
	if deriver.grant.Claims["envvault_session_id"] == "" {
		t.Fatalf("claims missing session id: %#v", deriver.grant.Claims)
	}
}

func TestIssuerRecordsSuccessfulCredentialIssueAuditWithoutSecrets(t *testing.T) {
	ctx := context.Background()
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.ProfileParentKey("backend-a/dev"), []byte("parent-secret")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	recorder := &recordingAudit{}
	service := local.NewIssuerWithAudit(fakeProfiles(), secrets, &fakeDeriver{}, recorder)

	credential, err := service.Issue(ctx, issuer.Grant{
		Profile: "backend-a/dev",
		Scopes:  []string{"repository:read"},
		TTL:     5 * time.Minute,
		Claims: map[string]any{
			"envvault_client":     "codex",
			"envvault_session_id": "hex:session",
			"envvault_project_id": "sha256:project",
		},
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if credential.AccessToken != "leased-jwt" {
		t.Fatalf("AccessToken = %q", credential.AccessToken)
	}

	if len(recorder.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(recorder.events))
	}
	got := recorder.events[0]
	if got.Event != audit.EventCredentialIssued {
		t.Fatalf("event = %q", got.Event)
	}
	if got.Profile != "backend-a/dev" {
		t.Fatalf("profile = %q", got.Profile)
	}
	if got.Kind != "process" {
		t.Fatalf("kind = %q", got.Kind)
	}
	if got.Resource != "https://api.dev.example.com" {
		t.Fatalf("resource = %q", got.Resource)
	}
	if got.TTLSeconds != 300 {
		t.Fatalf("ttl_seconds = %d", got.TTLSeconds)
	}
	if got.SessionID != "hex:session" {
		t.Fatalf("session_id = %q", got.SessionID)
	}
	if got.ProjectID != "sha256:project" {
		t.Fatalf("project_id = %q", got.ProjectID)
	}
	if got.Result != audit.ResultSuccess {
		t.Fatalf("result = %q", got.Result)
	}

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, secret := range []string{"leased-jwt", "parent-secret"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("audit event contains %q: %s", secret, raw)
		}
	}
}

func TestIssuerRecordsFailedCredentialIssueAuditWithoutSecrets(t *testing.T) {
	ctx := context.Background()
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.ProfileParentKey("backend-a/dev"), []byte("parent-secret")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	recorder := &recordingAudit{}
	deriver := &fakeDeriver{err: clerr.New(clerr.IssueFailed, "derive failed")}
	service := local.NewIssuerWithAudit(fakeProfiles(), secrets, deriver, recorder)

	_, err := service.Issue(ctx, issuer.Grant{
		Profile: "backend-a/dev",
		Scopes:  []string{"repository:read"},
		TTL:     5 * time.Minute,
		Claims: map[string]any{
			"envvault_session_id": "hex:failed-session",
		},
	})
	if err == nil {
		t.Fatal("Issue() error = nil, want error")
	}

	if len(recorder.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(recorder.events))
	}
	got := recorder.events[0]
	if got.Result != audit.ResultFailure {
		t.Fatalf("result = %q", got.Result)
	}
	if got.ErrorCode != clerr.IssueFailed {
		t.Fatalf("error_code = %q", got.ErrorCode)
	}
	if got.SessionID != "hex:failed-session" {
		t.Fatalf("session_id = %q", got.SessionID)
	}

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if bytes.Contains(raw, []byte("parent-secret")) || bytes.Contains(raw, []byte("leased-jwt")) {
		t.Fatalf("audit event contains secret material: %s", raw)
	}
}

func TestIssuerRejectsBrowserBootstrapTTLAboveProfileLimit(t *testing.T) {
	ctx := context.Background()
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.ProfileParentKey("admin-web/dev"), []byte("browser-parent-secret")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	deriver := &fakeDeriver{}
	service := local.NewIssuer(fakeProfiles(), secrets, deriver)

	_, err := service.Issue(ctx, issuer.Grant{
		Profile: "admin-web/dev",
		Scopes:  []string{"browser:session:create"},
		TTL:     61 * time.Second,
		Claims:  map[string]any{"envvault_purpose": "browser-bootstrap"},
	})
	if err == nil {
		t.Fatal("Issue() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ConfigInvalid {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ConfigInvalid)
	}
	if deriver.called {
		t.Fatal("deriver was called")
	}
}

type fakeProfileResolver map[string]profile.Profile

func (r fakeProfileResolver) Profile(name string) (profile.Profile, error) {
	p, ok := r[name]
	if !ok {
		return profile.Profile{}, clerr.New(clerr.ProfileNotFound, name)
	}
	return p, nil
}

type fakeDeriver struct {
	called    bool
	parentKey string
	grant     issuer.Grant
	err       error
}

func (d *fakeDeriver) DeriveJWT(_ context.Context, parentKey string, grant issuer.Grant) (issuer.Credential, error) {
	d.called = true
	d.parentKey = parentKey
	d.grant = grant
	if d.err != nil {
		return issuer.Credential{}, d.err
	}
	return issuer.Credential{
		AccessToken: "leased-jwt",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(grant.TTL),
		Scopes:      append([]string(nil), grant.Scopes...),
	}, nil
}

type panicStore struct{}

func (panicStore) Get(context.Context, keyring.Key) ([]byte, error) {
	panic("keyring should not be called")
}

func (panicStore) Put(context.Context, keyring.Key, []byte) error {
	panic("keyring should not be called")
}

func (panicStore) Delete(context.Context, keyring.Key) error {
	panic("keyring should not be called")
}

type recordingAudit struct {
	events []audit.Event
}

func (r *recordingAudit) Record(_ context.Context, event audit.Event) error {
	r.events = append(r.events, event)
	return nil
}

func fakeProfiles() fakeProfileResolver {
	return fakeProfileResolver{
		"backend-a/dev": {
			Name:        "backend-a/dev",
			Kind:        profile.KindProcess,
			Resource:    "https://api.dev.example.com",
			Scopes:      []string{"repository:read", "issue:read"},
			Claims:      map[string]string{"environment": "dev"},
			TokenTTL:    10 * time.Minute,
			MaxTokenTTL: 30 * time.Minute,
		},
		"admin-web/dev": {
			Name:              "admin-web/dev",
			Kind:              profile.KindBrowserSession,
			Resource:          "https://admin.dev.example.com",
			Scopes:            []string{"browser:session:create"},
			BootstrapTokenTTL: 60 * time.Second,
			LoginCodeTTL:      30 * time.Second,
			WebSessionTTL:     30 * time.Minute,
			ExchangeURL:       "https://admin.dev.example.com/auth/envvault/browser-sessions",
			CompleteURL:       "https://admin.dev.example.com/auth/envvault/complete",
			PostLoginURL:      "https://admin.dev.example.com/",
			AllowedHosts:      []string{"admin.dev.example.com"},
		},
	}
}
