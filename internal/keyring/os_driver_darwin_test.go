package keyring

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestDarwinSecurityDriverSetUsesExplicitDefaultKeychain(t *testing.T) {
	runner := &fakeDarwinSecurityRunner{
		results: []fakeDarwinSecurityResult{
			{out: []byte("\"/Users/me/Library/Keychains/login.keychain-db\"\n")},
			{},
		},
	}
	driver := newDarwinSecurityDriver(runner)

	if err := driver.Set("envvault", "envvault/credential/gemini-apikey/value", "secret-value"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	if len(runner.calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(runner.calls))
	}
	if got, want := runner.calls[0].args, []string{"default-keychain"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("default-keychain args = %#v, want %#v", got, want)
	}
	if got, want := runner.calls[1].args, []string{"-i"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("set args = %#v, want %#v", got, want)
	}

	stdin := runner.calls[1].stdin
	for _, want := range []string{
		"add-generic-password -U",
		"-s 'envvault'",
		"-a 'envvault/credential/gemini-apikey/value'",
		"'/Users/me/Library/Keychains/login.keychain-db'",
		"go-keyring-base64:",
	} {
		if !strings.Contains(stdin, want) {
			t.Fatalf("set stdin missing %q:\n%s", want, stdin)
		}
	}
	if strings.Contains(strings.Join(runner.calls[1].args, " "), "secret-value") {
		t.Fatalf("set args leaked raw secret: %#v", runner.calls[1].args)
	}
}

func TestDarwinSecurityDriverGetUsesExplicitDefaultKeychainAndDecodesValue(t *testing.T) {
	encoded := "go-keyring-base64:" + base64.StdEncoding.EncodeToString([]byte("secret-value"))
	runner := &fakeDarwinSecurityRunner{
		results: []fakeDarwinSecurityResult{
			{out: []byte("\"/Users/me/Library/Keychains/login.keychain-db\"\n")},
			{out: []byte(encoded + "\n")},
		},
	}
	driver := newDarwinSecurityDriver(runner)

	got, err := driver.Get("envvault", "envvault/credential/gemini-apikey/value")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got != "secret-value" {
		t.Fatalf("Get() = %q, want secret-value", got)
	}

	wantArgs := []string{
		"find-generic-password",
		"-s", "envvault",
		"-wa", "envvault/credential/gemini-apikey/value",
		"/Users/me/Library/Keychains/login.keychain-db",
	}
	if got := runner.calls[1].args; !reflect.DeepEqual(got, wantArgs) {
		t.Fatalf("find args = %#v, want %#v", got, wantArgs)
	}
}

func TestDarwinSecurityDriverReturnsDefaultKeychainError(t *testing.T) {
	runner := &fakeDarwinSecurityRunner{
		results: []fakeDarwinSecurityResult{
			{err: errors.New("default keychain missing")},
		},
	}
	driver := newDarwinSecurityDriver(runner)

	if err := driver.Set("envvault", "account", "secret"); err == nil {
		t.Fatal("Set() error = nil, want error")
	}
}

type fakeDarwinSecurityRunner struct {
	calls   []fakeDarwinSecurityCall
	results []fakeDarwinSecurityResult
}

type fakeDarwinSecurityCall struct {
	args  []string
	stdin string
}

type fakeDarwinSecurityResult struct {
	out []byte
	err error
}

func (r *fakeDarwinSecurityRunner) CombinedOutput(args []string, stdin string) ([]byte, error) {
	r.calls = append(r.calls, fakeDarwinSecurityCall{
		args:  append([]string(nil), args...),
		stdin: stdin,
	})
	if len(r.results) == 0 {
		return nil, nil
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result.out, result.err
}
