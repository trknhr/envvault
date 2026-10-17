package keyring

import (
	"context"
	"errors"

	"github.com/trknhr/envvault/internal/clerr"
)

const defaultService = "envvault"

type driver interface {
	Get(service, account string) (string, error)
	Set(service, account, password string) error
	Delete(service, account string) error
}

type osStore struct {
	service string
	driver  driver
}

func NewOSStore() Store {
	return newOSStore(defaultService, platformDriver{})
}

func newOSStore(service string, driver driver) Store {
	return osStore{service: service, driver: driver}
}

// Get reports a missing item as ErrNotFound. A locked or failing store still
// uses the generic unavailable error so import does not treat it as empty.
func (s osStore) Get(ctx context.Context, key Key) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	value, err := s.driver.Get(s.service, string(key))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, missingKeyError(key)
		}
		return nil, keyringUnavailable()
	}
	return []byte(value), nil
}

func (s osStore) Put(ctx context.Context, key Key, value []byte) error {
	return s.call(ctx, func() error {
		return s.driver.Set(s.service, string(key), string(value))
	})
}

func (s osStore) Delete(ctx context.Context, key Key) error {
	return s.call(ctx, func() error {
		return s.driver.Delete(s.service, string(key))
	})
}

// call checks cancellation before touching the OS driver and maps every
// driver failure to the same unavailable error so backend text cannot leak.
func (s osStore) call(ctx context.Context, op func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := op(); err != nil {
		return keyringUnavailable()
	}
	return nil
}

func keyringUnavailable() error {
	return clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable")
}
