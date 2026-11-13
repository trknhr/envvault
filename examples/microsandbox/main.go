// This example provides an interactive agent launcher and a fake-credential smoke test.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	m "github.com/superradcompany/microsandbox/sdk/go"
)

func main() {
	if err := run(); err != nil {
		if errors.Is(err, errAgentInterrupted) {
			os.Exit(130)
		}
		fmt.Fprintln(os.Stderr, "Microsandbox:", err)
		var commandExit *agentExitError
		if errors.As(err, &commandExit) && commandExit.code > 0 && commandExit.code < 256 {
			os.Exit(commandExit.code)
		}
		os.Exit(1)
	}
}

func run() (resultErr error) {
	setupOnly := flag.Bool("setup", false, "install/check the isolated native runtime only")
	licenses := flag.Bool("licenses", false, "print the bundled Microsandbox SDK license")
	flag.Parse()
	if *licenses {
		data, err := agentAssets.ReadFile("MICROSANDBOX_LICENSE")
		if err != nil {
			return err
		}
		fmt.Print(string(data))
		return nil
	}
	if os.Getenv("MSB_HOME") == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		// macOS Unix sockets require a short runtime path.
		if err := os.Setenv("MSB_HOME", filepath.Join(home, ".envvault-msb-trial")); err != nil {
			return err
		}
	}
	if args := flag.Args(); len(args) > 0 {
		return runAgent(args)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	fmt.Printf("Checking Microsandbox SDK %s and its native runtime...\n", m.SDKVersion())
	if _, err := m.EnsureRuntime(ctx, m.RuntimeConfig{}, m.InstallOptions{}); err != nil {
		return fmt.Errorf("native runtime setup: %w", err)
	}
	if *setupOnly {
		fmt.Println("PASS: isolated native runtime is available")
		return nil
	}

	// This loopback receiver accepts only the current fake token. Plain HTTP and
	// RequireTLSIdentity=false are intentional for this local canary test only.
	var expected atomic.Value
	expected.Store(canary())
	var accepted atomic.Int32
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+expected.Load().(string) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			accepted.Add(1)
			_, _ = fmt.Fprintln(w, "credential accepted")
		}),
	}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	const guestVar = "ENVVAULT_TEST_TOKEN"
	const host = "host.microsandbox.internal"
	const hostSource = "ENVVAULT_MICROSANDBOX_FAKE_TOKEN"
	const placeholder = "envvault://microsandbox/local-trial"
	allowPlaintext := false
	name := fmt.Sprintf("envvault-msb-trial-%d", time.Now().UnixNano())
	fmt.Println("Creating a Linux microVM with access only to the local test receiver...")
	sb, err := m.CreateSandbox(ctx, name,
		m.WithImage("alpine:3.23"),
		m.WithRegistryAnonymous(),
		m.WithMemory(512),
		m.WithCPUs(1),
		m.WithNetwork(&m.NetworkConfig{
			DefaultEgress:  m.PolicyActionDeny,
			DefaultIngress: m.PolicyActionDeny,
			Rules: []m.PolicyRule{
				m.Rule.AllowDNS(),
				{Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress, Destination: "host", Protocol: m.PolicyProtocolTCP, Port: strconv.Itoa(port)},
			},
		}),
		m.WithSecrets(m.Secret.Env(guestVar, expected.Load().(string), m.SecretEnvOptions{
			Allow:              []string{host},
			Placeholder:        placeholder,
			RequireTLSIdentity: &allowPlaintext,
			Substitution:       m.SecretSubstitution{HeaderFields: []string{"authorization"}},
		})),
	)
	if err != nil {
		return fmt.Errorf("create VM: %w", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		stopErr := sb.Stop(cleanupCtx)
		closeErr := sb.Close()
		removeErr := m.RemoveSandbox(cleanupCtx, name)
		resultErr = errors.Join(resultErr, stopErr, closeErr, removeErr)
	}()
	command := func(command string) (string, error) {
		out, err := sb.Shell(ctx, command)
		if err != nil {
			return "", err
		}
		if out.ExitCode() != 0 {
			return "", fmt.Errorf("guest command failed with exit %d (output withheld)", out.ExitCode())
		}
		return strings.TrimSpace(out.Stdout()), nil
	}
	bootID, err := command("cat /proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	if _, err := command(`test "$ENVVAULT_TEST_TOKEN" = 'envvault://microsandbox/local-trial' && printf ready`); err != nil {
		return fmt.Errorf("placeholder check: %w", err)
	}
	fmt.Println("PASS: Go SDK boots a Linux VM; the guest receives a placeholder")
	request := fmt.Sprintf(`wget -q -T 10 -O - --header="Authorization: Bearer $ENVVAULT_TEST_TOKEN" http://%s:%d/`, host, port)
	if _, err := command(request); err != nil {
		return fmt.Errorf("initial injection: %w", err)
	}
	if accepted.Load() != 1 {
		return errors.New("test receiver did not accept the injected credential")
	}
	fmt.Println("PASS: host-side credential substitution reaches the local receiver")

	modify := func(spec m.SecretModifySpec) error {
		plan, err := sb.Modify(ctx, m.ModifyOptions{
			Secrets: map[string]m.SecretModifySpec{guestVar: spec},
			Policy:  m.ModificationPolicyNoRestart,
		})
		if err != nil {
			return err
		}
		if !plan.Applied || len(plan.Conflicts) != 0 || len(plan.Changes) == 0 {
			return errors.New("secret modification was not applied")
		}
		for _, change := range plan.Changes {
			if change.Disposition != "live" {
				return fmt.Errorf("secret update requires %s", change.Disposition)
			}
		}
		return nil
	}
	expected.Store(canary())
	if err := os.Setenv(hostSource, expected.Load().(string)); err != nil {
		return err
	}
	defer os.Unsetenv(hostSource)
	if err := modify(m.SecretModifySpec{Env: hostSource}); err != nil {
		return fmt.Errorf("live rotation: %w", err)
	}
	if _, err := command(request); err != nil {
		return fmt.Errorf("rotated injection: %w", err)
	}
	if accepted.Load() != 2 {
		return errors.New("rotated credential was not accepted")
	}
	fmt.Println("PASS: credential rotation applies without restarting")
	if err := modify(m.SecretModifySpec{AllowedHosts: []string{"unrelated.invalid"}}); err != nil {
		return fmt.Errorf("live host restriction: %w", err)
	}
	if _, err := command(request); err == nil || accepted.Load() != 2 {
		return errors.New("revoked secret destination was not blocked")
	}
	if err := modify(m.SecretModifySpec{AllowedHosts: []string{host}}); err != nil {
		return fmt.Errorf("live host restoration: %w", err)
	}
	if _, err := command(request); err != nil {
		return fmt.Errorf("restored injection: %w", err)
	}
	if accepted.Load() != 3 {
		return errors.New("restored destination did not accept the credential")
	}
	fmt.Println("PASS: secret host permissions block and allow without restarting")
	blocked, err := sb.Shell(ctx, "wget -q -T 3 -O /dev/null http://example.com/")
	if err != nil || blocked.ExitCode() == 0 {
		return errors.New("unlisted direct egress check failed")
	}
	fmt.Println("PASS: unlisted direct internet traffic is blocked")
	after, err := command("cat /proc/sys/kernel/random/boot_id")
	if err != nil || after != bootID {
		return errors.New("VM boot identity changed during the live updates")
	}
	fmt.Println("PASS: the same VM remained running throughout")
	return nil
}

func canary() string {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic("generate fake credential")
	}
	return hex.EncodeToString(raw[:])
}
