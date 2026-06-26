package keyring

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/trknhr/envvault/internal/clerr"
)

func TestOSStoreUsesServiceAndKeyAsAccount(t *testing.T) {
	driver := &fakeDriver{}
	store := newOSStore("envvault-test", driver)
	ctx := context.Background()
	key := ProfileParentKey("backend-a/dev")

	if err := store.Put(ctx, key, []byte("parent-secret")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(got, []byte("parent-secret")) {
		t.Fatalf("Get() = %q, want parent-secret", got)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	if driver.service != "envvault-test" {
		t.Fatalf("service = %q", driver.service)
	}
	if driver.account != string(key) {
		t.Fatalf("account = %q, want %q", driver.account, key)
	}
	if driver.deleted != string(key) {
		t.Fatalf("deleted = %q, want %q", driver.deleted, key)
	}
}

func TestOSStoreMapsDriverErrorsWithoutLeakingSecret(t *testing.T) {
	driver := &fakeDriver{err: errors.New("backend returned parent-secret")}
	store := newOSStore("envvault-test", driver)

	err := store.Put(context.Background(), ProfileParentKey("backend-a/dev"), []byte("parent-secret"))
	if err == nil {
		t.Fatal("Put() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.KeyringUnavailable {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.KeyringUnavailable)
	}
	if bytes.Contains([]byte(err.Error()), []byte("parent-secret")) {
		t.Fatalf("error leaked secret: %q", err.Error())
	}
}

type fakeDriver struct {
	service  string
	account  string
	password string
	deleted  string
	err      error
}

func (d *fakeDriver) Get(service, account string) (string, error) {
	d.service = service
	d.account = account
	if d.err != nil {
		return "", d.err
	}
	return d.password, nil
}

func (d *fakeDriver) Set(service, account, password string) error {
	d.service = service
	d.account = account
	d.password = password
	return d.err
}

func (d *fakeDriver) Delete(service, account string) error {
	d.service = service
	d.account = account
	d.deleted = account
	return d.err
}
