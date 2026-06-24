package keyring_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/keyring"
)

func TestSecretKeyNamesMatchSpecHierarchy(t *testing.T) {
	tests := []struct {
		name string
		got  keyring.Key
		want string
	}{
		{name: "hmac", got: keyring.TalosHMACKey(), want: "credlease/talos/hmac/current"},
		{name: "signing", got: keyring.TalosSigningKey("kid-1"), want: "credlease/talos/signing/kid-1"},
		{name: "parent", got: keyring.ProfileParentKey("backend-a/dev"), want: "credlease/profile/backend-a/dev/parent-key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.got) != tt.want {
				t.Fatalf("key = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestMemoryStoreCopiesSecretsOnPutAndGet(t *testing.T) {
	ctx := context.Background()
	store := keyring.NewMemoryStore()
	value := []byte("parent-secret")

	if err := store.Put(ctx, keyring.ProfileParentKey("backend-a/dev"), value); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	value[0] = 'X'

	got, err := store.Get(ctx, keyring.ProfileParentKey("backend-a/dev"))
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(got, []byte("parent-secret")) {
		t.Fatalf("Get() = %q, want parent-secret", got)
	}
	got[0] = 'Y'

	gotAgain, err := store.Get(ctx, keyring.ProfileParentKey("backend-a/dev"))
	if err != nil {
		t.Fatalf("Get() second error = %v", err)
	}
	if !bytes.Equal(gotAgain, []byte("parent-secret")) {
		t.Fatalf("Get() second = %q, want parent-secret", gotAgain)
	}
}

func TestMemoryStoreMissingParentKeyUsesParentKeyCode(t *testing.T) {
	_, err := keyring.NewMemoryStore().Get(context.Background(), keyring.ProfileParentKey("backend-a/dev"))
	if err == nil {
		t.Fatal("Get() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ParentKeyMissing {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ParentKeyMissing)
	}
}

func TestUnavailableStoreFailsClosed(t *testing.T) {
	ctx := context.Background()
	store := keyring.UnavailableStore{}
	key := keyring.ProfileParentKey("backend-a/dev")

	if _, err := store.Get(ctx, key); codeOf(err) != clerr.KeyringUnavailable {
		t.Fatalf("Get() code = %q, want %q", codeOf(err), clerr.KeyringUnavailable)
	}
	if err := store.Put(ctx, key, []byte("parent-secret")); codeOf(err) != clerr.KeyringUnavailable {
		t.Fatalf("Put() code = %q, want %q", codeOf(err), clerr.KeyringUnavailable)
	}
	if err := store.Delete(ctx, key); codeOf(err) != clerr.KeyringUnavailable {
		t.Fatalf("Delete() code = %q, want %q", codeOf(err), clerr.KeyringUnavailable)
	}
}

func codeOf(err error) clerr.Code {
	code, _ := clerr.CodeOf(err)
	return code
}
