// This test-only plugin uses the real EnvVault broker with an in-memory
// credential and a loopback mock upstream. It never accesses the OS keyring.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/cli"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/sandboxplugin"
	"github.com/trknhr/envvault/internal/sandboxsession"
	sessionagentinfra "github.com/trknhr/envvault/internal/sandboxsession/agentinfra"
)

type profiles struct{ profile profile.Profile }

func (p profiles) Profile(name string) (profile.Profile, error) {
	if name != p.profile.Name {
		return profile.Profile{}, clerr.New(clerr.ProfileNotFound, "test profile not found")
	}
	return p.profile, nil
}

func main() {
	sessionMode := len(os.Args) >= 3 && os.Args[1] == "sandbox" && os.Args[2] == "exec"
	if !sessionMode && (len(os.Args) < 4 || os.Args[1] != "sandbox" || os.Args[2] != "plugin" || os.Args[3] != "serve") {
		fmt.Fprintln(os.Stderr, "test helper expects sandbox plugin serve or sandbox exec")
		os.Exit(1)
	}
	flags := flag.NewFlagSet("mock-plugin", flag.ExitOnError)
	listen := flags.String("gateway-listen", "127.0.0.1:0", "gateway listener")
	host := flags.String("gateway-host", "", "gateway advertised host")
	if !sessionMode {
		_ = flags.Parse(os.Args[4:])
	}
	const canary = "ENVVAULT_BRIDGE_UPSTREAM_CANARY_NOT_A_REAL_KEY"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/probe" || r.Header.Get("Authorization") != "Bearer "+canary {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	secrets := keyring.NewMemoryStore()
	_ = secrets.Put(context.Background(), keyring.CredentialValue("bridge-test-key"), []byte(canary))
	broker := &sandboxplugin.Broker{
		Profiles: profiles{profile.Profile{
			Name: "bridge-test", Kind: profile.KindProviderProxy,
			CredentialName: "bridge-test-key", Provider: "generic", AuthMode: "bearer",
			TargetURL: upstream.URL, AllowedPaths: []string{"/probe"}, AllowedMethods: []string{"GET"},
			LocalTokenTTL: time.Minute, ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
		}},
		Secrets: secrets, ListenAddress: *listen, AdvertiseHost: *host,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if sessionMode {
		app := cli.New(cli.Options{Profiles: broker.Profiles, Secrets: secrets, Stdin: os.Stdin,
			SandboxSessionRuntimes: map[string]sandboxsession.Runtime{"agent-infra": sessionagentinfra.Runtime{}},
		})
		os.Exit(app.Run(ctx, os.Args[1:], os.Stdout, os.Stderr))
	}
	if err := (sandboxplugin.Server{Broker: broker}).Serve(ctx, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mock plugin failed")
		os.Exit(1)
	}
}
