package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	backendgo "github.com/trknhr/credlease/examples/backend-go"
)

type appConfig struct {
	Addr          string
	JWKS          []byte
	Issuer        string
	Resource      string
	ClockSkew     time.Duration
	CompleteURL   string
	PostLoginURL  string
	LoginCodeTTL  time.Duration
	WebSessionTTL time.Duration
	SecureCookies bool
	Now           func() time.Time
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	_ = stdout

	config, err := parseConfig(args)
	if err != nil {
		fmt.Fprintf(stderr, "credlease example backend: %v\n", err)
		return 2
	}
	handler, err := newHandler(config)
	if err != nil {
		fmt.Fprintf(stderr, "credlease example backend: %v\n", err)
		return 1
	}

	listener, err := net.Listen("tcp", config.Addr)
	if err != nil {
		fmt.Fprintf(stderr, "credlease example backend: listen %s: %v\n", config.Addr, err)
		return 1
	}
	defer listener.Close()

	server := &http.Server{
		Addr:              config.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		errc <- server.Serve(listener)
	}()
	fmt.Fprintf(stderr, "credlease example backend listening on %s\n", listener.Addr().String())

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(stderr, "credlease example backend: shutdown: %v\n", err)
			return 1
		}
		if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "credlease example backend: serve: %v\n", err)
			return 1
		}
		return 0
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "credlease example backend: serve: %v\n", err)
			return 1
		}
		return 0
	}
}

func parseConfig(args []string) (appConfig, error) {
	flags := flag.NewFlagSet("backend", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	var jwksPath string
	config := appConfig{}
	flags.StringVar(&config.Addr, "addr", "127.0.0.1:8080", "listen address")
	flags.StringVar(&jwksPath, "jwks", "", "path to Credlease JWKS JSON")
	flags.StringVar(&config.Issuer, "issuer", "", "expected Credlease issuer")
	flags.StringVar(&config.Resource, "resource", "", "expected Credlease resource")
	flags.StringVar(&config.CompleteURL, "complete-url", "", "browser session complete URL")
	flags.StringVar(&config.PostLoginURL, "post-login-url", "", "fixed post-login URL")
	flags.DurationVar(&config.ClockSkew, "clock-skew", 30*time.Second, "JWT clock skew")
	flags.DurationVar(&config.LoginCodeTTL, "login-code-ttl", 30*time.Second, "browser login code TTL")
	flags.DurationVar(&config.WebSessionTTL, "web-session-ttl", 30*time.Minute, "browser web session TTL")
	flags.BoolVar(&config.SecureCookies, "secure-cookies", false, "set Secure on browser session cookies")

	if err := flags.Parse(args); err != nil {
		return appConfig{}, err
	}
	if flags.NArg() != 0 {
		return appConfig{}, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	for _, required := range []struct {
		flag  string
		value string
	}{
		{flag: "--jwks", value: jwksPath},
		{flag: "--issuer", value: config.Issuer},
		{flag: "--resource", value: config.Resource},
		{flag: "--complete-url", value: config.CompleteURL},
		{flag: "--post-login-url", value: config.PostLoginURL},
	} {
		if required.value == "" {
			return appConfig{}, fmt.Errorf("%s is required", required.flag)
		}
	}

	jwks, err := os.ReadFile(jwksPath)
	if err != nil {
		return appConfig{}, fmt.Errorf("read --jwks %q: %w", jwksPath, err)
	}
	config.JWKS = jwks
	return config, nil
}

func newHandler(config appConfig) (http.Handler, error) {
	backend, err := backendgo.New(backendgo.Config{
		JWKS:          config.JWKS,
		Issuer:        config.Issuer,
		Resource:      config.Resource,
		ClockSkew:     config.ClockSkew,
		Now:           config.Now,
		CompleteURL:   config.CompleteURL,
		PostLoginURL:  config.PostLoginURL,
		LoginCodeTTL:  config.LoginCodeTTL,
		WebSessionTTL: config.WebSessionTTL,
		SecureCookies: config.SecureCookies,
	})
	if err != nil {
		return nil, err
	}
	return backend.Handler(), nil
}
