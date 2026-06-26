package admin_test

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/admin"
	"github.com/trknhr/envvault/internal/keyring"
)

func TestNewTokenReturnsURLSafeToken(t *testing.T) {
	token, err := admin.NewToken()
	if err != nil {
		t.Fatalf("NewToken() error = %v", err)
	}
	if len(token) < 32 {
		t.Fatalf("token length = %d, want at least 32", len(token))
	}
	if strings.ContainsAny(token, "+/=") {
		t.Fatalf("token contains non-url-safe base64 characters: %q", token)
	}
}

func TestServiceServePublishesLocalURLAndStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdout := &lockedBuffer{}
	service := admin.Service{Secrets: keyring.NewMemoryStore()}
	errCh := make(chan error, 1)

	go func() {
		errCh <- service.Serve(ctx, admin.ServeRequest{
			Addr:   "127.0.0.1:0",
			Token:  "admin-token",
			Stdout: stdout,
		})
	}()

	adminURL := waitForAdminURL(t, stdout)
	response, err := http.Get(adminURL)
	if err != nil {
		t.Fatalf("GET admin URL error = %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET admin URL status = %d, want 200", response.StatusCode)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not stop after context cancellation")
	}
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(value)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func waitForAdminURL(t *testing.T, stdout interface{ String() string }) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, field := range strings.Fields(stdout.String()) {
			if strings.HasPrefix(field, "http://") {
				return field
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("admin URL not printed; stdout=%q", stdout.String())
	return ""
}
