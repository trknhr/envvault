package cli_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/trknhr/envvault/internal/cli"
	"github.com/trknhr/envvault/internal/keyring"
)

func TestCredentialResolveHostConsumer(t *testing.T) {
	// sbx invokes helpers from a fresh directory, without project configuration.
	t.Chdir(t.TempDir())
	ctx := context.Background()
	store := keyring.NewMemoryStore()
	if err := store.Put(ctx, keyring.CredentialValue("app/dev"), []byte("fake-resolver-value")); err != nil {
		t.Fatal(err)
	}
	app := cli.New(cli.Options{Secrets: store})
	for _, ref := range []string{"envvault://app/dev", "envvault://app/%64ev"} {
		var stdout, stderr bytes.Buffer
		code := app.Run(ctx, []string{"credential", "resolve", ref}, &stdout, &stderr)
		if code != 0 || stdout.String() != "fake-resolver-value" || stderr.Len() != 0 {
			t.Fatalf("unexpected resolver result: code=%d, output length=%d, error length=%d", code, stdout.Len(), stderr.Len())
		}
	}
}

func TestCredentialResolveRejectsInvalidReferences(t *testing.T) {
	store := &resolverStore{value: []byte("secret-canary")}
	for _, ref := range []string{"app/dev", "secret-canary", "envvault://", "envvault://app/../dev", "envvault://app/dev?secret-canary", "envvault://app/dev/token", "envvault://app/dev/base-url", "envvault://app/dev/value", "envvault://app%2fdev"} {
		var stdout, stderr bytes.Buffer
		code := cli.New(cli.Options{Secrets: store}).Run(context.Background(), []string{"credential", "resolve", ref}, &stdout, &stderr)
		if code == 0 || stdout.Len() != 0 || bytes.Contains(stderr.Bytes(), []byte("secret-canary")) {
			t.Fatal("invalid reference was accepted or echoed")
		}
	}
	if store.calls != 0 {
		t.Fatal("invalid reference accessed the credential store")
	}
}

func TestCredentialResolveRejectsUnsafeHeaderValues(t *testing.T) {
	for _, value := range []string{"", " ", " leading", "trailing\n", "embedded\r\nheader", "nul\x00byte", "tab\tbyte", "del\x7fbyte"} {
		store := keyring.NewMemoryStore()
		if err := store.Put(context.Background(), keyring.CredentialValue("app/dev"), []byte(value)); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := cli.New(cli.Options{Secrets: store}).Run(context.Background(), []string{"credential", "resolve", "envvault://app/dev"}, &stdout, &stderr)
		if code == 0 || stdout.Len() != 0 {
			t.Fatal("unsafe value was emitted")
		}
	}
}

func TestCredentialResolveRejectsMissingCredentialsAndStores(t *testing.T) {
	for _, opts := range []cli.Options{
		{},
		{Secrets: keyring.NewMemoryStore()},
		{Secrets: keyring.UnavailableStore{}},
	} {
		var stdout, stderr bytes.Buffer
		if cli.New(opts).Run(context.Background(), []string{"credential", "resolve", "envvault://app/dev"}, &stdout, &stderr) == 0 || stdout.Len() != 0 {
			t.Fatal("unavailable credential was accepted")
		}
	}
}

func TestCredentialResolveRefusesTerminalBeforeLookup(t *testing.T) {
	store := &resolverStore{value: []byte("secret-canary")}
	app := cli.New(cli.Options{Secrets: store, StdoutIsTerminal: func() bool { return true }})
	var stdout, stderr bytes.Buffer
	if app.Run(context.Background(), []string{"credential", "resolve", "envvault://app/dev"}, &stdout, &stderr) == 0 || stdout.Len() != 0 {
		t.Fatal("credential was emitted to a terminal")
	}
	if store.calls != 0 {
		t.Fatal("terminal output accessed the credential store")
	}
	if bytes.Contains(stderr.Bytes(), store.value) {
		t.Fatal("terminal refusal leaked value")
	}
}

type resolverStore struct {
	keyring.Store
	value []byte
	err   error
	calls int
}

func (s *resolverStore) Get(context.Context, keyring.Key) ([]byte, error) {
	s.calls++
	return s.value, s.err
}

type resolverWriter struct{ short bool }

func (w resolverWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, errors.New("secret-canary")
}

func TestCredentialResolveClearsBuffersAndRedactsFailures(t *testing.T) {
	for _, tc := range []struct {
		backendErr error
		writer     io.Writer
	}{
		{writer: io.Discard},
		{backendErr: errors.New("secret-canary"), writer: io.Discard},
		{writer: resolverWriter{}},
		{writer: resolverWriter{short: true}},
	} {
		value := []byte("secret-canary")
		app := cli.New(cli.Options{Secrets: &resolverStore{value: value, err: tc.backendErr}})
		var stderr bytes.Buffer
		code := app.Run(context.Background(), []string{"credential", "resolve", "envvault://app/dev"}, tc.writer, &stderr)
		if tc.backendErr != nil || tc.writer != io.Discard {
			if code == 0 {
				t.Fatal("failed consumer or backend reported success")
			}
		} else if code != 0 {
			t.Fatal("resolver failed")
		}
		if bytes.Contains(stderr.Bytes(), []byte("secret-canary")) {
			t.Fatal("diagnostics leaked value")
		}
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("secret buffer was not cleared")
		}
	}
}

func TestCredentialResolveClearsRejectedHeaderValue(t *testing.T) {
	value := []byte("secret-canary\r\nheader")
	app := cli.New(cli.Options{Secrets: &resolverStore{value: value}})
	var stdout, stderr bytes.Buffer
	if app.Run(context.Background(), []string{"credential", "resolve", "envvault://app/dev"}, &stdout, &stderr) == 0 || stdout.Len() != 0 {
		t.Fatal("unsafe header value was emitted")
	}
	if bytes.Contains(stderr.Bytes(), []byte("secret-canary")) {
		t.Fatal("invalid header diagnostic leaked value")
	}
	if !bytes.Equal(value, make([]byte, len(value))) {
		t.Fatal("rejected secret buffer was not cleared")
	}
}
