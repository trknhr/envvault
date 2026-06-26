package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/keyring"
)

const DefaultAddr = "127.0.0.1:17890"

type Service struct {
	ConfigPath string
	Secrets    keyring.Store
}

type ServeRequest struct {
	Addr     string
	Token    string
	TokenEnv string
	Stdout   io.Writer
}

func NewToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", clerr.Wrap(clerr.ConfigInvalid, "generate admin token", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func (s Service) Serve(ctx context.Context, request ServeRequest) error {
	addr := request.Addr
	if addr == "" {
		addr = DefaultAddr
	}
	if strings.TrimSpace(request.Token) == "" {
		return clerr.New(clerr.ConfigInvalid, "admin token is required")
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "listen admin server", err)
	}
	defer listener.Close()

	server := &http.Server{
		Handler: Server{
			ConfigPath: s.ConfigPath,
			Secrets:    s.Secrets,
			Token:      request.Token,
		}.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()

	if request.Stdout != nil {
		fmt.Fprintf(request.Stdout, "EnvVault admin: %s\n", OpenURL(listener.Addr().String(), request.Token))
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return clerr.Wrap(clerr.CleanupFailed, "shutdown admin server", err)
		}
		err := <-errCh
		if err == nil || err == http.ErrServerClosed {
			return nil
		}
		return err
	case err := <-errCh:
		if err == nil || err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func OpenURL(addr, token string) string {
	host := addr
	if strings.HasPrefix(host, "[::]") {
		host = "127.0.0.1" + strings.TrimPrefix(host, "[::]")
	}
	return fmt.Sprintf("http://%s/?token=%s", host, url.QueryEscape(token))
}
