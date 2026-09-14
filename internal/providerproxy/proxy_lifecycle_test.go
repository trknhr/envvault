package providerproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServerCloseBeforeServeClosesListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	// Hold Serve until after Close to reproduce shutdown before the serving
	// goroutine registers its listener, without relying on scheduler timing.
	apiKey := []byte("upstream-test-canary")
	token := []byte("temporary-test-capability")
	server := &Server{
		server:   &http.Server{},
		listener: listener,
		apiKey:   apiKey,
		token:    token,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 50*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatal("gateway still accepted connections after Close before Serve")
	}
	for _, value := range [][]byte{apiKey, token} {
		for _, b := range value {
			if b != 0 {
				t.Fatal("Close did not clear credential buffers")
			}
		}
	}
	if err := server.Close(ctx); err != nil {
		t.Fatalf("repeated Close() error = %v", err)
	}
	if err := server.server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Serve(after Close) error = %v, want ErrServerClosed", err)
	}
}
