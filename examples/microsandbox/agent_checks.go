package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	m "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/trknhr/envvault/internal/authstate"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/connection/authprovider"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/projectbinding"
)

const agentCheckHost = "credential-check.envvault.invalid"

// This fixture is used only by agent-check. It never reads or writes the OS
// credential store, and never reflects a credential into the guest response.
type agentCredentialCheck struct {
	store          keyring.Store
	expected       atomic.Value
	arrivals       atomic.Int32
	githubArrivals atomic.Int32
	origin         *httptest.Server
	filename       string
	config         config.File
	auth           authstate.Store
	metadata       authstate.Metadata
	git            http.Handler
	gitWrites      atomic.Int32
}

func startAgentCheckProxy(filename string) (*agentProxy, *agentCredentialCheck, error) {
	check := &agentCredentialCheck{store: keyring.NewMemoryStore()}
	check.filename = filepath.Join(filepath.Dir(filename), "envvault.yaml")
	cfg, err := config.DefaultFile()
	if err != nil {
		return nil, nil, err
	}
	check.auth = authstate.Store{Dir: filepath.Join(filepath.Dir(filename), "auth-profiles"), Keys: check.store}
	check.metadata = authstate.Metadata{Name: "microsandbox/check", Provider: "generic", Format: "json", TokenField: "/access_token"}
	if err := check.rotate(context.Background()); err != nil {
		return nil, nil, err
	}
	cfg.Version = 2
	cfg.AuthProfiles = map[string]string{"microsandbox/check": check.metadata.ID}
	check.config = cfg
	if err := config.Save(check.filename, cfg); err != nil {
		return nil, nil, err
	}
	check.git, err = prepareAgentGitCheck(filepath.Dir(filename))
	if err != nil {
		return nil, nil, err
	}
	var address atomic.Value
	proxy, err := startAgentProxyWithVault(filename, func(ctx context.Context, authority string) (net.Conn, error) {
		if authority == agentCheckHost+":443" || authority == "api.github.com:443" || authority == "github.com:443" {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address.Load().(string))
		}
		return dialAgentPublic(ctx, authority)
	}, &agentVault{filename: check.filename, dataDir: filepath.Dir(filename), identity: projectbinding.Identity{Root: filepath.Dir(filename)}})
	if err != nil {
		return nil, nil, err
	}
	proxy.credentials = authprovider.Provider{ConfigPath: check.filename, DataDir: filepath.Dir(filename), Secrets: check.store}
	certificate, err := proxy.tls.certificate(agentCheckHost)
	if err != nil {
		proxy.Close()
		return nil, nil, err
	}
	githubCertificate, err := proxy.tls.certificate("api.github.com")
	if err != nil {
		proxy.Close()
		return nil, nil, err
	}
	gitCertificate, err := proxy.tls.certificate("github.com")
	if err != nil {
		proxy.Close()
		return nil, nil, err
	}
	check.origin = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "github.com" {
			username, password, ok := r.BasicAuth()
			if !ok || username != "x-access-token" || password != check.expected.Load().(string) {
				http.Error(w, "credential mismatch", 401)
				return
			}
			if strings.HasSuffix(r.URL.Path, "/git-receive-pack") || r.URL.Query().Get("service") == "git-receive-pack" {
				check.gitWrites.Add(1)
			}
			check.git.ServeHTTP(w, r)
			return
		}
		if r.Host == "api.github.com" {
			check.githubArrivals.Add(1)
			if r.URL.Path != "/user" || r.Header.Get("Authorization") != "Bearer "+check.expected.Load().(string) {
				http.Error(w, "credential mismatch", 401)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"login":"envvault-local-check"}`)
			return
		}
		check.arrivals.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+check.expected.Load().(string) && r.Header.Get("X-API-Key") != check.expected.Load().(string) {
			http.Error(w, "credential mismatch", http.StatusUnauthorized)
			return
		}
		io.WriteString(w, "accepted")
	}))
	check.origin.TLS = &tls.Config{Certificates: []tls.Certificate{*certificate, *githubCertificate, *gitCertificate}, MinVersion: tls.VersionTLS12}
	check.origin.StartTLS()
	address.Store(check.origin.Listener.Addr().String())
	roots, err := x509.SystemCertPool()
	if err != nil {
		proxy.Close()
		check.origin.Close()
		return nil, nil, err
	}
	roots.AppendCertsFromPEM(proxy.tls.publicPEM)
	proxy.tls.transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if err := check.rotate(context.Background()); err != nil {
		proxy.Close()
		check.origin.Close()
		return nil, nil, err
	}
	return proxy, check, nil
}

func checkAgentGitHub(ctx context.Context, sb *m.Sandbox, check *agentCredentialCheck) error {
	check.config.Profiles["github-check"] = config.Profile{Kind: profile.KindProviderProxy, CredentialName: "microsandbox/check", Provider: "generic",
		TargetURL: "https://api.github.com", AllowedMethods: []string{"GET"}, AllowedPaths: []string{"/user"}, LocalTokenTTL: config.Duration(time.Minute)}
	if err := config.Save(check.filename, check.config); err != nil {
		return err
	}
	const prefix = "GH_TOKEN=envvault://microsandbox/check GH_CONFIG_DIR=/tmp/envvault-gh-check GH_NO_UPDATE_NOTIFIER=1 GH_PROMPT_DISABLED=1 GH_TELEMETRY=0 DO_NOT_TRACK=1 "
	for i := 0; i < 2; i++ {
		if value, err := checkedAgentShell(ctx, sb, prefix+"gh api user --jq .login"); err != nil || value != "envvault-local-check" {
			return errors.New("sandbox gh did not authenticate through the host proxy")
		}
		if i == 0 {
			if err := check.rotate(ctx); err != nil {
				return err
			}
		}
	}
	if check.githubArrivals.Load() != 2 {
		return errors.New("unexpected gh receiver requests")
	}
	if _, err := checkedAgentShell(ctx, sb, prefix+"gh api repos/trknhr/envvault"); err == nil {
		return errors.New("gh escaped its saved API path scope")
	}
	if check.githubArrivals.Load() != 2 {
		return errors.New("blocked gh request reached upstream")
	}
	fmt.Println("PASS: gh uses a placeholder through the host proxy; rotation works and unauthorized API paths are blocked")
	return nil
}

func (c *agentCredentialCheck) rotate(ctx context.Context) error {
	value := "test-only-" + rand.Text()
	c.expected.Store(value)
	document, _ := json.Marshal(map[string]string{"access_token": value, "refresh_token": "refresh-test-only-" + rand.Text()})
	defer keyring.Zero(document)
	metadata, err := c.auth.Put(ctx, c.metadata, document)
	if err == nil {
		c.metadata = metadata
	}
	return err
}

func checkAgentCredentials(ctx context.Context, sb *m.Sandbox, filename string, policy agentPolicy, check *agentCredentialCheck) error {
	if _, err := checkedAgentShell(ctx, sb, `test "$ENVVAULT_CHECK_TOKEN" = envvault://microsandbox/check`); err != nil {
		return errors.New("guest did not receive the EnvVault reference")
	}
	if _, err := checkedAgentShell(ctx, sb, `test -r "$ENVVAULT_CREDENTIALS_FILE" && test ! -w "$ENVVAULT_CREDENTIALS_FILE" && grep -q envvault://microsandbox/check "$ENVVAULT_CREDENTIALS_FILE" && ! grep -q test-only- "$ENVVAULT_CREDENTIALS_FILE"`); err != nil {
		return errors.New("guest reference catalog was not public, read-only metadata")
	}
	request := `curl -sS --max-time 10 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ENVVAULT_CHECK_TOKEN" https://` + agentCheckHost
	if status, err := checkedAgentShell(ctx, sb, request+"/outside"); err != nil || status != "401" || check.arrivals.Load() != 0 {
		return errors.New("default profile scope allowed a credential without a saved destination")
	}
	// Exercise the explicit broader mode separately, then restore profile scope.
	network := policy
	network.EnvVaultScope = "network"
	if err := writeAgentPolicy(filename, network); err != nil {
		return err
	}
	if status, err := checkedAgentShell(ctx, sb, `curl -sS --max-time 10 -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer envvault://microsandbox/missing' https://`+agentCheckHost+"/api"); err != nil || status != "401" || check.arrivals.Load() != 0 {
		return errors.New("unknown credential reference was not blocked")
	}
	if status, err := checkedAgentShell(ctx, sb, request+"/outside"); err != nil || status != "200" {
		return errors.New("default access required a saved credential destination")
	}
	for i := 0; i < 2; i++ {
		if status, err := checkedAgentShell(ctx, sb, request+"/v1/api"); err != nil || status != "200" {
			return errors.New("host-side EnvVault credential substitution failed")
		}
		if i == 0 {
			if err := check.rotate(ctx); err != nil {
				return err
			}
		}
	}
	if status, err := checkedAgentShell(ctx, sb, `curl -sS --max-time 10 -o /dev/null -w '%{http_code}' -H 'X-API-Key: envvault://microsandbox/check' https://`+agentCheckHost+"/api"); err != nil || status != "200" {
		return errors.New("API-key header substitution failed")
	}
	if check.arrivals.Load() != 4 {
		return errors.New("unexpected credential receiver requests")
	}
	delete(check.config.AuthProfiles, "microsandbox/check")
	if err := config.Save(check.filename, check.config); err != nil {
		return err
	}
	if status, err := checkedAgentShell(ctx, sb, request+"/v1/api"); err != nil || status != "401" || check.arrivals.Load() != 4 {
		return errors.New("removed credential binding remained usable")
	}
	check.config.AuthProfiles["microsandbox/check"] = check.metadata.ID
	if err := config.Save(check.filename, check.config); err != nil {
		return err
	}
	// A new credential becomes usable without any destination profile, sandbox
	// binding, process environment changes, or VM restart.
	document, _ := json.Marshal(map[string]string{"access_token": check.expected.Load().(string)})
	defer keyring.Zero(document)
	added, err := check.auth.Put(ctx, authstate.Metadata{Name: "microsandbox/added", Provider: "generic", Format: "json", TokenField: "/access_token"}, document)
	if err != nil {
		return err
	}
	check.config.AuthProfiles["microsandbox/added"] = added.ID
	if err := config.Save(check.filename, check.config); err != nil {
		return err
	}
	if status, err := checkedAgentShell(ctx, sb, `curl -sS --max-time 10 -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer envvault://microsandbox/added' https://`+agentCheckHost+"/v1/added"); err != nil || status != "200" {
		return errors.New("new EnvVault credential did not become usable live")
	}
	if err := waitAgentCatalogReference(ctx, sb, "envvault://microsandbox/added"); err != nil {
		return err
	}
	if _, err := checkedAgentShell(ctx, sb, `test ! -w "$ENVVAULT_CREDENTIALS_FILE" && grep -q envvault://microsandbox/added "$ENVVAULT_CREDENTIALS_FILE" && ! grep -q test-only- "$ENVVAULT_CREDENTIALS_FILE"`); err != nil {
		return errors.New("new public reference did not reach the guest catalog")
	}
	check.config.Profiles["check"] = config.Profile{Kind: profile.KindProviderProxy, CredentialName: "microsandbox/check", Provider: "generic",
		TargetURL: "https://" + agentCheckHost + "/v1", AllowedMethods: []string{"GET"}, AllowedPaths: []string{"/api"}, LocalTokenTTL: config.Duration(time.Minute)}
	if err := config.Save(check.filename, check.config); err != nil {
		return err
	}
	strict := policy
	strict.EnvVaultScope = "profiles"
	if err := writeAgentPolicy(filename, strict); err != nil {
		return err
	}
	if status, err := checkedAgentShell(ctx, sb, request+"/outside"); err != nil || status != "403" || check.arrivals.Load() != 5 {
		return errors.New("optional profile scope was not enforced live")
	}
	if status, err := checkedAgentShell(ctx, sb, request+"/v1/api"); err != nil || status != "200" {
		return errors.New("saved profile scope did not authorize its matching request")
	}
	if err := writeAgentPolicy(filename, policy); err != nil {
		return err
	}
	fmt.Println("PASS: all EnvVault references auto-discover; host-only injection, rotation, addition, and revocation apply live")
	return nil
}

func waitAgentCatalogReference(ctx context.Context, sb *m.Sandbox, reference string) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if data, err := sb.FS().ReadString(ctx, agentCatalogPath); err == nil && strings.Contains(data, reference) {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("live reference catalog update timed out")
		case <-ticker.C:
		}
	}
}

func waitAgentFile(ctx context.Context, sb *m.Sandbox, filename, expected string) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if value, err := sb.FS().ReadString(ctx, filename); err == nil && strings.TrimSpace(value) == expected {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("live update did not reach %s", filename)
		case <-ticker.C:
		}
	}
}

func checkAgentProcesses(ctx context.Context, sb *m.Sandbox, filename string, policy agentPolicy) error {
	if _, err := checkedAgentShell(ctx, sb, `test "$(id -u)" = 1000 && test ! -w `+agentPIDsPath+` && test ! -w /usr/local/bin/envvault-agent-exec && grep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status && grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status`); err != nil {
		return errors.New("agent privilege boundary failed")
	}
	// A bounded C helper forks at most 32 children. It stays running while the
	// host raises the limit, so recovery cannot be explained by a new process.
	if err := sb.FS().WriteString(ctx, "/tmp/envvault-process-check.c", agentProcessCheckSource); err != nil {
		return err
	}
	if _, err := checkedAgentShell(ctx, sb, "cc -O2 -o /tmp/envvault-process-check /tmp/envvault-process-check.c"); err != nil {
		return err
	}
	limited := policy
	limited.MaxProcesses = 16
	if err := writeAgentPolicy(filename, limited); err != nil {
		return err
	}
	if err := waitAgentFile(ctx, sb, agentPIDsPath, "16"); err != nil {
		return err
	}
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := checkedAgentShell(runCtx, sb, "exec /tmp/envvault-process-check")
		done <- err
	}()
	if err := waitAgentFile(ctx, sb, "/tmp/envvault-process-check.ready", "blocked"); err != nil {
		return errors.New("kernel did not block a bounded process creation test")
	}
	current, err := sb.FS().ReadString(ctx, "/sys/fs/cgroup/envvault-agent/pids.current")
	count, parseErr := strconv.Atoi(strings.TrimSpace(current))
	if err != nil || parseErr != nil || count > 16 || count < 2 {
		return errors.New("process count did not respect its kernel limit")
	}
	if err := os.WriteFile(filename, []byte("{"), 0600); err != nil {
		return err
	}
	if err := waitAgentFile(ctx, sb, agentPIDsPath, "0"); err != nil {
		return errors.New("invalid host policy did not stop new forks")
	}
	limited.MaxProcesses = 64
	if err := writeAgentPolicy(filename, limited); err != nil {
		return err
	}
	select {
	case err := <-done:
		if err != nil {
			return errors.New("same process could not fork after its live limit increased")
		}
	case <-runCtx.Done():
		return errors.New("live process limit recovery timed out")
	}
	if err := writeAgentPolicy(filename, policy); err != nil {
		return err
	}
	if err := waitAgentFile(ctx, sb, agentPIDsPath, strconv.Itoa(policy.MaxProcesses)); err != nil {
		return err
	}
	fmt.Println("PASS: unprivileged agent cannot raise its limit; kernel blocks forks, fails closed, and recovers after a live increase")
	return nil
}

const agentProcessCheckSource = `
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
  pid_t children[32]; int n = 0, blocked = 0, result = 1;
  for (int i = 0; i < 32; i++) {
    pid_t p = fork();
    if (p == -1) { blocked = errno == EAGAIN; break; }
    if (p == 0) { for (;;) pause(); }
    children[n++] = p;
  }
  FILE *ready = fopen("/tmp/envvault-process-check.ready", "w");
  if (ready) { fputs(blocked ? "blocked" : "failed", ready); fclose(ready); }
  if (blocked) for (int i = 0; i < 2000; i++) {
    int limit = 0;
    FILE *f = fopen("/sys/fs/cgroup/envvault-agent/pids.max", "r");
    if (f) { if (fscanf(f, "%d", &limit) != 1) limit = 0; fclose(f); }
    if (limit >= 64) {
      pid_t p = fork();
      if (p == 0) _exit(0);
      if (p > 0) { int status; waitpid(p, &status, 0); result = status != 0; }
      break;
    }
    usleep(10000);
  }
  for (int i = 0; i < n; i++) kill(children[i], SIGKILL);
  for (int i = 0; i < n; i++) waitpid(children[i], NULL, 0);
  return result;
}
`
