package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/trknhr/credlease/pkg/browsersession"
	"github.com/trknhr/credlease/pkg/verifier"
	_ "modernc.org/sqlite"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:]))
}

func run(ctx context.Context, args []string) int {
	var jwksPath, issuer, resource, sqlitePath, listen string
	flagSet := flag.NewFlagSet("browser-session-go", flag.ContinueOnError)
	flagSet.StringVar(&jwksPath, "jwks", "credlease-jwks.json", "path to exported Credlease JWKS")
	flagSet.StringVar(&issuer, "issuer", "", "expected Credlease issuer")
	flagSet.StringVar(&resource, "resource", "http://127.0.0.1:8080", "expected Credlease resource")
	flagSet.StringVar(&sqlitePath, "sqlite", "browser-session.sqlite", "SQLite replay/code store path")
	flagSet.StringVar(&listen, "listen", "127.0.0.1:8080", "listen address")
	if err := flagSet.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	jwks, err := os.ReadFile(jwksPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	tokenVerifier, err := verifier.New(verifier.Options{
		JWKS:          jwks,
		Issuer:        issuer,
		Resource:      resource,
		RequireIssuer: issuer != "",
		AllowedAlgs:   []string{"RS256", "EdDSA"},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer db.Close()
	store, err := browsersession.NewSQLiteStore(ctx, db, time.Now)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	server := browsersession.Server{
		Verifier: verifier.BrowserBootstrapVerifier{
			Verifier: tokenVerifier,
			Scopes:   []string{"browser:session:create"},
		},
		ReplayStore:   store,
		CodeStore:     store,
		SessionIssuer: cookieIssuer{},
		CompleteURL:   resource + "/auth/credlease/complete",
		PostLoginURL:  resource + "/",
		LoginCodeTTL:  30 * time.Second,
		WebSessionTTL: 30 * time.Minute,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/credlease/browser-sessions", server.Exchange)
	mux.HandleFunc("/auth/credlease/complete", server.Complete)
	if err := http.ListenAndServe(listen, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

type cookieIssuer struct{}

func (cookieIssuer) Issue(ctx context.Context, _ browsersession.BrowserGrant, ttl time.Duration) (browsersession.SessionCookie, error) {
	if err := ctx.Err(); err != nil {
		return browsersession.SessionCookie{}, err
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return browsersession.SessionCookie{}, err
	}
	return browsersession.SessionCookie{
		Name:     "credlease_admin_session",
		Value:    base64.RawURLEncoding.EncodeToString(raw[:]),
		Path:     "/",
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
	}, nil
}
