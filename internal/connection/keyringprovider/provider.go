// Package keyringprovider adapts the existing OS credential store to the
// connection credential-provider boundary.
package keyringprovider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/keyring"
)

type Provider struct {
	Store keyring.Store
	Now   func() time.Time
}

func (p Provider) Acquire(ctx context.Context, request connection.CredentialRequest) (connection.CredentialLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(request.SessionID) == "" || strings.TrimSpace(request.SubjectID) == "" {
		return nil, configInvalid("credential request session and subject are required")
	}
	if err := request.Spec.Validate(); err != nil {
		return nil, err
	}
	if request.Spec.Provider != "keyring" || request.Spec.Issuance != connection.IssuanceStatic {
		return nil, configInvalid("keyring provider supports only static keyring credentials")
	}
	if request.TTL <= 0 {
		return nil, configInvalid("credential request ttl must be positive")
	}
	if request.Spec.MaxTTL > 0 && request.TTL > request.Spec.MaxTTL {
		return nil, configInvalid("credential request ttl exceeds credential max ttl")
	}
	ref, recognized, err := envref.ParseValue(request.Spec.Ref)
	if err != nil || !recognized || ref.Part != envref.PartDefault {
		return nil, configInvalid("keyring credential reference is invalid")
	}
	if p.Store == nil {
		return nil, clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable")
	}
	value, err := p.Store.Get(ctx, keyring.CredentialValue(ref.Profile))
	if err != nil {
		return nil, err
	}
	id, err := newLeaseID()
	if err != nil {
		zero(value)
		return nil, err
	}
	now := p.now()
	return &lease{
		id:        id,
		expiresAt: now.Add(request.TTL),
		value:     value,
		now:       p.Now,
	}, nil
}

func (p Provider) Revoke(ctx context.Context, credential connection.CredentialLease) error {
	owned, ok := credential.(*lease)
	if !ok {
		return configInvalid("credential lease was not issued by keyring provider")
	}
	owned.revoke()
	if ctx != nil {
		return ctx.Err()
	}
	return nil
}

func (p Provider) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

type lease struct {
	mu        sync.Mutex
	id        string
	expiresAt time.Time
	value     []byte
	revoked   bool
	now       func() time.Time
}

func (l *lease) ID() string {
	return l.id
}

func (l *lease) ExpiresAt() time.Time {
	return l.expiresAt
}

func (l *lease) WithValue(ctx context.Context, use func([]byte) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if use == nil {
		return configInvalid("credential callback is required")
	}
	l.mu.Lock()
	now := time.Now()
	if l.now != nil {
		now = l.now()
	}
	if l.revoked || !now.Before(l.expiresAt) {
		l.mu.Unlock()
		return clerr.New(clerr.IssueFailed, "credential lease is expired or revoked")
	}
	value := append([]byte(nil), l.value...)
	l.mu.Unlock()
	defer zero(value)
	return use(value)
}

func (l *lease) String() string {
	return "keyring credential lease [REDACTED]"
}

func (l *lease) GoString() string {
	return "keyring credential lease [REDACTED]"
}

func (l *lease) revoke() {
	l.mu.Lock()
	defer l.mu.Unlock()
	zero(l.value)
	l.value = nil
	l.revoked = true
}

func newLeaseID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", clerr.Wrap(clerr.IssueFailed, "generate credential lease id", err)
	}
	return "cred_" + hex.EncodeToString(raw[:]), nil
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func configInvalid(message string) error {
	return clerr.New(clerr.ConfigInvalid, message)
}
