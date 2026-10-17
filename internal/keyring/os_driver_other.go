//go:build !darwin

package keyring

import (
	"errors"

	oskeyring "github.com/zalando/go-keyring"
)

type platformDriver struct{}

func (platformDriver) Get(service, account string) (string, error) {
	value, err := oskeyring.Get(service, account)
	if errors.Is(err, oskeyring.ErrNotFound) {
		return "", ErrNotFound
	}
	return value, err
}

func (platformDriver) Set(service, account, password string) error {
	return oskeyring.Set(service, account, password)
}

func (platformDriver) Delete(service, account string) error {
	return oskeyring.Delete(service, account)
}
