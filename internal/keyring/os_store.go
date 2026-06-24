package keyring

import (
	"context"

	"github.com/trknhr/credlease/internal/clerr"
	oskeyring "github.com/zalando/go-keyring"
)

const defaultService = "credlease"

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

func (s osStore) Get(ctx context.Context, key Key) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	value, err := s.driver.Get(s.service, string(key))
	if err != nil {
		return nil, keyringUnavailable()
	}
	return []byte(value), nil
}

func (s osStore) Put(ctx context.Context, key Key, value []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.driver.Set(s.service, string(key), string(value)); err != nil {
		return keyringUnavailable()
	}
	return nil
}

func (s osStore) Delete(ctx context.Context, key Key) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.driver.Delete(s.service, string(key)); err != nil {
		return keyringUnavailable()
	}
	return nil
}

type platformDriver struct{}

func (platformDriver) Get(service, account string) (string, error) {
	return oskeyring.Get(service, account)
}

func (platformDriver) Set(service, account, password string) error {
	return oskeyring.Set(service, account, password)
}

func (platformDriver) Delete(service, account string) error {
	return oskeyring.Delete(service, account)
}

func keyringUnavailable() error {
	return clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable")
}
