package keyring

import (
	"context"
	"strings"
	"sync"

	"github.com/trknhr/envvault/internal/clerr"
)

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
		return clerr.New(clerr.ParentKeyMissing, "parent key missing")
	}
	return clerr.New(clerr.KeyringUnavailable, "secret missing")
}

func unavailable() error {
	return clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable")
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out
}
