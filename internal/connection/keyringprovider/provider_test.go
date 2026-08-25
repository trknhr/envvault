package keyringprovider_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/connection/keyringprovider"
	"github.com/trknhr/envvault/internal/keyring"
)

func TestProviderAcquiresUsesAndRevokesCredential(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store := keyring.NewMemoryStore()
	if err := store.Put(ctx, keyring.CredentialValue("openai/dev"), []byte("secret-canary")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	provider := keyringprovider.Provider{Store: store, Now: func() time.Time { return now }}
	credential, err := provider.Acquire(ctx, request(time.Minute))
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if credential.ID() == "" || credential.ExpiresAt() != now.Add(time.Minute) {
		t.Fatalf("lease metadata = %q/%s", credential.ID(), credential.ExpiresAt())
	}
	var got string
	if err := credential.WithValue(ctx, func(value []byte) error {
		got = string(value)
		value[0] = 'X'
		return nil
	}); err != nil {
		t.Fatalf("WithValue() error = %v", err)
	}
	if got != "secret-canary" {
		t.Fatal("credential callback returned an unexpected value")
	}
	if err := credential.WithValue(ctx, func(value []byte) error {
		if string(value) != "secret-canary" {
			t.Fatal("provider-owned credential value was mutated")
		}
		return nil
	}); err != nil {
		t.Fatalf("second WithValue() error = %v", err)
	}

	if err := provider.Revoke(ctx, credential); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if err := credential.WithValue(ctx, func([]byte) error { return nil }); err == nil {
		t.Fatal("WithValue() after revoke error = nil")
	}
}

func TestProviderLeaseFormattingIsRedacted(t *testing.T) {
	ctx := context.Background()
	store := keyring.NewMemoryStore()
	if err := store.Put(ctx, keyring.CredentialValue("openai/dev"), []byte("secret-canary")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	credential, err := (keyringprovider.Provider{Store: store}).Acquire(ctx, request(time.Minute))
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	formatted := fmt.Sprintf("%v %#v", credential, credential)
	if strings.Contains(formatted, "secret-canary") || !strings.Contains(formatted, "REDACTED") {
		t.Fatal("formatted credential lease was not redacted")
	}
}

func TestProviderRejectsUnsupportedRequestAndExpiredLease(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	store := keyring.NewMemoryStore()
	if err := store.Put(ctx, keyring.CredentialValue("openai/dev"), []byte("secret-canary")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	provider := keyringprovider.Provider{Store: store, Now: func() time.Time { return now }}

	invalid := request(time.Minute)
	invalid.Spec.Provider = "vault"
	if _, err := provider.Acquire(ctx, invalid); errorCode(err) != clerr.ConfigInvalid {
		t.Fatalf("unsupported Acquire() error = %v", err)
	}
	credential, err := provider.Acquire(ctx, request(time.Minute))
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	now = now.Add(time.Minute)
	if err := credential.WithValue(ctx, func([]byte) error { return nil }); errorCode(err) != clerr.IssueFailed {
		t.Fatalf("expired WithValue() error = %v", err)
	}

	overlong := request(2 * time.Minute)
	overlong.Spec.MaxTTL = time.Minute
	if _, err := provider.Acquire(ctx, overlong); errorCode(err) != clerr.ConfigInvalid {
		t.Fatalf("overlong Acquire() error = %v", err)
	}
}

func TestProviderRevokesBufferEvenWhenContextIsCanceled(t *testing.T) {
	ctx := context.Background()
	store := keyring.NewMemoryStore()
	if err := store.Put(ctx, keyring.CredentialValue("openai/dev"), []byte("secret-canary")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	provider := keyringprovider.Provider{Store: store}
	credential, err := provider.Acquire(ctx, request(time.Minute))
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := provider.Revoke(canceled, credential); err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("Revoke() error = %v", err)
	}
	if err := credential.WithValue(ctx, func([]byte) error { return nil }); errorCode(err) != clerr.IssueFailed {
		t.Fatalf("WithValue() after canceled revoke error = %v", err)
	}
}

func request(ttl time.Duration) connection.CredentialRequest {
	return connection.CredentialRequest{
		SessionID: "session-1",
		SubjectID: "sandbox-1",
		Spec: connection.CredentialSpec{
			Provider: "keyring",
			Ref:      "envvault://openai/dev",
			Issuance: connection.IssuanceStatic,
		},
		TTL: ttl,
	}
}

func errorCode(err error) clerr.Code {
	code, _ := clerr.CodeOf(err)
	return code
}
