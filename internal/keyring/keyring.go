package keyring

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/trknhr/envvault/internal/clerr"
)

// ErrNotFound is wrapped by Get when the named item is absent. The returned
// error text stays generic and does not include the missing value.
var ErrNotFound = errors.New("keyring item not found")

type Key string

type Store interface {
	Get(ctx context.Context, key Key) ([]byte, error)
	Put(ctx context.Context, key Key, value []byte) error
	Delete(ctx context.Context, key Key) error
}

func TalosHMACKey() Key {
	return "envvault/talos/hmac/current"
}

func TalosSigningKey(kid string) Key {
	return Key("envvault/talos/signing/" + kid)
}

func ProfileParentKey(profile string) Key {
	return Key("envvault/profile/" + profile + "/parent-key")
}

func CredentialValue(name string) Key {
	return Key("envvault/credential/" + name + "/value")
}

func ProviderAPIKey(profile string) Key {
	return CredentialValue(profile)
}

type MemoryStore struct {
	mu      sync.Mutex
	secrets map[Key][]byte
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{secrets: map[Key][]byte{}}
}

func (s *MemoryStore) Get(_ context.Context, key Key) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	value, ok := s.secrets[key]
	if !ok {
		return nil, missingKeyError(key)
	}
	return cloneBytes(value), nil
}

func (s *MemoryStore) Put(_ context.Context, key Key, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.secrets[key] = cloneBytes(value)
	return nil
}

func (s *MemoryStore) Delete(_ context.Context, key Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.secrets, key)
	return nil
}

type UnavailableStore struct{}

func (UnavailableStore) Get(context.Context, Key) ([]byte, error) {
	return nil, unavailable()
}

func (UnavailableStore) Put(context.Context, Key, []byte) error {
	return unavailable()
}

func (UnavailableStore) Delete(context.Context, Key) error {
	return unavailable()
}

func missingKeyError(key Key) error {
	if strings.HasSuffix(string(key), "/parent-key") {
		return clerr.Wrap(clerr.ParentKeyMissing, "parent key missing", ErrNotFound)
	}
	return clerr.Wrap(clerr.KeyringUnavailable, "secret missing", ErrNotFound)
}

func unavailable() error {
	return keyringUnavailable()
}

// Zero overwrites a secret buffer. A nil or empty slice is a no-op.
func Zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out
}
