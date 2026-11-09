// Package authprovider dispatches host credentials to opaque keyring secrets
// or encrypted structured authentication profiles.
package authprovider

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/trknhr/envvault/internal/authstate"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/connection/keyringprovider"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/keyring"
)

type Provider struct {
	ConfigPath string
	DataDir    string
	Secrets    keyring.Store
	HTTP       *http.Client
	Now        func() time.Time
}

func (p Provider) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}
func (p Provider) Store() authstate.Store {
	return authstate.Store{Dir: filepath.Join(p.DataDir, "auth-profiles"), Keys: p.Secrets}
}

// HostOnly lets direct environment/file resolvers reject managed auth profiles,
// including when a stale opaque key with the same name exists in the keyring.
func (p Provider) HostOnly(ctx context.Context, name string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	cfg, err := config.LoadOrDefault(p.ConfigPath)
	if err != nil {
		return false, errors.New("credential configuration unavailable")
	}
	_, exists := cfg.AuthProfiles[name]
	return exists, nil
}

func (p Provider) Acquire(ctx context.Context, request connection.CredentialRequest) (connection.CredentialLease, error) {
	ref, recognized, err := envref.ParseValue(request.Spec.Ref)
	if err != nil || !recognized || ref.Part != envref.PartDefault {
		return nil, errors.New("invalid authentication reference")
	}
	cfg, err := config.LoadOrDefault(p.ConfigPath)
	if err != nil {
		return nil, errors.New("credential configuration unavailable")
	}
	if _, exists := cfg.AuthProfiles[ref.Profile]; !exists {
		base := keyringprovider.Provider{Store: p.Secrets, Now: p.Now}
		check, err := base.Acquire(ctx, request)
		if err != nil {
			return nil, err
		}
		_ = base.Revoke(context.WithoutCancel(ctx), check)
		return &lease{provider: p, name: ref.Profile, request: request, id: "auth_" + rand.Text(), expires: p.now().Add(request.TTL)}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(request.SessionID) == "" || strings.TrimSpace(request.SubjectID) == "" || request.TTL <= 0 || request.Spec.Validate() != nil || request.Spec.MaxTTL > 0 && request.TTL > request.Spec.MaxTTL {
		return nil, errors.New("invalid authentication credential request")
	}
	if request.Spec.Provider != "keyring" && request.Spec.Provider != "auth-profile" || request.Spec.Issuance != connection.IssuanceStatic {
		return nil, errors.New("unsupported authentication credential provider")
	}
	return &lease{provider: p, name: ref.Profile, request: request, managed: true, id: "auth_" + rand.Text(), expires: p.now().Add(request.TTL)}, nil
}

func (p Provider) Revoke(ctx context.Context, credential connection.CredentialLease) error {
	if owned, ok := credential.(*lease); ok {
		owned.mu.Lock()
		owned.revoked = true
		owned.mu.Unlock()
		return nil
	}
	return (keyringprovider.Provider{Store: p.Secrets, Now: p.Now}).Revoke(ctx, credential)
}

type lease struct {
	id       string
	request  connection.CredentialRequest
	managed  bool
	provider Provider
	name     string
	expires  time.Time
	mu       sync.Mutex
	revoked  bool
}

func (l *lease) ID() string           { return l.id }
func (l *lease) ExpiresAt() time.Time { return l.expires }
func (*lease) String() string         { return "authentication lease [REDACTED]" }
func (*lease) GoString() string       { return "authentication lease [REDACTED]" }
func (l *lease) WithValue(ctx context.Context, use func([]byte) error) error {
	l.mu.Lock()
	revoked := l.revoked
	l.mu.Unlock()
	if revoked || !l.provider.now().Before(l.expires) || use == nil {
		return errors.New("authentication lease expired or revoked")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !l.managed {
		base := keyringprovider.Provider{Store: l.provider.Secrets, Now: l.provider.Now}
		request := l.request
		request.TTL = l.expires.Sub(l.provider.now())
		fresh, err := base.Acquire(ctx, request)
		if err != nil {
			return err
		}
		defer base.Revoke(context.WithoutCancel(ctx), fresh)
		return fresh.WithValue(ctx, use)
	}
	cfg, err := config.Load(l.provider.ConfigPath)
	if err != nil {
		return errors.New("authentication profile unavailable")
	}
	id, exists := cfg.AuthProfiles[l.name]
	if !exists {
		return errors.New("authentication profile revoked")
	}
	var value []byte
	err = l.provider.Store().Update(ctx, id, func(record *authstate.Record) (bool, error) {
		if record.Metadata.Name != l.name {
			return false, errors.New("authentication profile identity mismatch")
		}
		expiry, err := authstate.Expiry(record.Document, record.Metadata.ExpiresField)
		if err != nil {
			return false, err
		}
		changed := false
		if !expiry.IsZero() && !expiry.After(l.provider.now().Add(30*time.Second)) {
			if record.Metadata.Provider != "github" {
				return false, errors.New("authentication expired; replace it on the host")
			}
			fresh, err := (authstate.GitHub{HTTP: l.provider.HTTP, Now: l.provider.Now}).Refresh(ctx, record.Metadata, record.Document)
			if err != nil {
				return false, err
			}
			keyring.Zero(record.Document)
			record.Document = fresh
			record.Metadata.Format = "json"
			record.Metadata.TokenField = "/access_token"
			record.Metadata.ExpiresField = "/expires_at"
			record.Metadata.RefreshField = "/refresh_token"
			changed = true
		}
		value, err = authstate.Token(record.Document, record.Metadata.TokenField)
		return changed, err
	})
	defer keyring.Zero(value)
	if err != nil {
		return err
	}
	l.mu.Lock()
	revoked = l.revoked
	l.mu.Unlock()
	if revoked || ctx.Err() != nil {
		return errors.New("authentication lease revoked or cancelled")
	}
	return use(value)
}

// Valid is a metadata-only revocation check for brokers with open streams.
func (l *lease) Valid(ctx context.Context) error {
	l.mu.Lock()
	revoked := l.revoked
	l.mu.Unlock()
	if revoked || !l.provider.now().Before(l.expires) {
		return errors.New("credential lease revoked or expired")
	}
	if !l.managed {
		return nil
	}
	cfg, err := config.Load(l.provider.ConfigPath)
	if err != nil {
		return errors.New("authentication configuration unavailable")
	}
	id, exists := cfg.AuthProfiles[l.name]
	if !exists {
		return errors.New("authentication profile revoked")
	}
	metadata, err := l.provider.Store().ReadMetadata(id)
	if err != nil || metadata.Name != l.name {
		return errors.New("authentication profile unavailable")
	}
	return ctx.Err()
}
