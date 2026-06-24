package fakekeyring

import (
	"context"

	"github.com/trknhr/credlease/internal/keyring"
)

var _ keyring.Store = (*Store)(nil)

type Store struct {
	inner *keyring.MemoryStore
}

func New() *Store {
	return &Store{inner: keyring.NewMemoryStore()}
}

func (s *Store) Get(ctx context.Context, key keyring.Key) ([]byte, error) {
	return s.inner.Get(ctx, key)
}

func (s *Store) Put(ctx context.Context, key keyring.Key, value []byte) error {
	return s.inner.Put(ctx, key, value)
}

func (s *Store) Delete(ctx context.Context, key keyring.Key) error {
	return s.inner.Delete(ctx, key)
}
