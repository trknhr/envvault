//go:build !darwin

package keyring

import oskeyring "github.com/zalando/go-keyring"

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
