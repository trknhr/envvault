package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	m "github.com/superradcompany/microsandbox/sdk/go"
)

const agentImage = "envvault-codex-msb:0.166.0-v4"
const agentHomeVolume = "envvault-msb-codex-home"

var errAgentInterrupted = errors.New("agent session interrupted")

func runAgent(args []string) (resultErr error) {
	mode := args[0]
	switch mode {
	case "codex", "login", "shell", "agent-setup", "agent-check", "rules":
	default:
		return errors.New("use ./agent [codex|login|shell|agent-setup|agent-check|rules]")
	}
	_, source, _, _ := runtime.Caller(0)
	exampleDir := filepath.Dir(source)
	repoDir := filepath.Clean(filepath.Join(exampleDir, "../.."))
	stateDir, err := filepath.Abs(os.Getenv("MSB_HOME"))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	resolvedState, err := filepath.EvalSymlinks(stateDir)
	if err != nil {
		return err
	}
	resolvedRepo, err := filepath.EvalSymlinks(repoDir)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(resolvedRepo, resolvedState)
	if err != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("MSB_HOME must be outside the mounted repository")
	}
	policyPath := filepath.Join(stateDir, "agent-policy.json")
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		data, err := os.ReadFile(filepath.Join(exampleDir, "agent-policy.json"))
		if err != nil {
			return err
		}
		if err := os.WriteFile(policyPath, data, 0o600); err != nil {
			return err
		}
	}
	policy, err := readAgentPolicy(policyPath)
	if err != nil {
		return err
	}
	if mode == "rules" {
		data, _ := json.MarshalIndent(policy, "", "  ")
		fmt.Printf("Host policy: %s\n%s\nWorkspace: %s -> /workspace (read/write)\nPersistent home volume: %s -> /home/agent\n", policyPath, data, repoDir, agentHomeVolume)
		fmt.Println("Only gateway DNS and the host proxy are reachable directly. The host proxy checks each HTTPS request against the listed hosts on port 443.")
		fmt.Println("Removed hosts' connections close within the 250ms polling interval, subject to scheduling. The proxy CA private key stays on the host.")
		fmt.Printf("Agent UID/GID: 1000:1000, no capabilities; live process/thread limit: %d. EnvVault credential values resolve on the host only.\n", policy.MaxProcesses)
		if len(policy.NativeAuthHosts) > 0 {
			fmt.Printf("Native authentication allowed for: %s. Native login credentials are readable in the guest home.\n", strings.Join(policy.NativeAuthHosts, ", "))
		}
		if policy.EnvVault {
			vault, err := defaultAgentVault(repoDir)
			if err != nil {
				return err
			}
			snapshot, err := vault.load()
			if err != nil {
				return err
			}
			fmt.Printf("EnvVault: automatic discovery enabled; %d references, scope %s, %d saved destination rules. Guest catalog: %s\n", len(snapshot.references), policy.EnvVaultScope, len(snapshot.routes), agentCatalogPath)
		}
		return nil
	}
	// One writer per Linux home disk. The lock is outside the guest mounts.
	lock, err := os.OpenFile(filepath.Join(stateDir, "agent.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("another agent session is using this home; exit it first")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if _, err := m.EnsureRuntime(ctx, m.RuntimeConfig{}, m.InstallOptions{}); err != nil {
		return err
	}
	if err := prepareAgentImage(ctx, exampleDir, mode == "agent-setup"); err != nil {
		return err
	}
	if mode == "agent-setup" {
		return nil
	}
	if _, err := m.GetVolume(ctx, agentHomeVolume); err != nil {
		var typed *m.Error
		if !errors.As(err, &typed) || typed.Kind != m.ErrVolumeNotFound {
			return err
		}
		if _, err := m.CreateVolume(ctx, agentHomeVolume, m.WithVolumeKind(m.VolumeKindDisk), m.WithVolumeSize(8192)); err != nil {
			return err
		}
	}
	if mode == "agent-check" {
		// Test policy transitions without editing the operator's active rules.
		policy = agentPolicy{HTTPSHosts: []string{"proxy.golang.org", "sum.golang.org", "storage.googleapis.com", agentCheckHost, "api.github.com", "github.com"}, MaxProcesses: 512, EnvVault: true, EnvVaultScope: "profiles"}
		dir, err := os.MkdirTemp(stateDir, "policy-check-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		policyPath = filepath.Join(dir, "policy.json")
		if err := writeAgentPolicy(policyPath, policy); err != nil {
			return err
		}
	}
	var proxy *agentProxy
	var credentialCheck *agentCredentialCheck
	if mode == "agent-check" {
		proxy, credentialCheck, err = startAgentCheckProxy(policyPath)
	} else {
		proxy, err = startAgentProxy(policyPath, repoDir)
	}
	if err != nil {
		return err
	}
	defer proxy.Close()
	if credentialCheck != nil {
		defer credentialCheck.origin.Close()
	}
	proxyURL := fmt.Sprintf("http://host.microsandbox.internal:%d", proxy.port())
	env := map[string]string{
		"HOME": "/home/agent", "CODEX_HOME": "/home/agent/.codex",
		"GOPATH": "/home/agent/go", "GOCACHE": "/home/agent/.cache/go-build",
		"HTTP_PROXY": proxyURL, "HTTPS_PROXY": proxyURL,
		"http_proxy": proxyURL, "https_proxy": proxyURL, "NO_PROXY": "", "no_proxy": "",
		"PATH":                      "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TERM":                      "xterm-256color",
		"SSL_CERT_FILE":             "/etc/ssl/certs/ca-certificates.crt",
		"CODEX_CA_CERTIFICATE":      "/etc/ssl/certs/ca-certificates.crt",
		"NODE_EXTRA_CA_CERTS":       "/usr/local/share/ca-certificates/envvault-agent.crt",
		"ENVVAULT_CREDENTIALS_FILE": agentCatalogPath,
		"GIT_CONFIG_SYSTEM":         "/etc/envvault/gitconfig",
	}
	for _, binding := range policy.Credentials {
		env[binding.Environment] = binding.Reference
	}
	if mode == "agent-check" {
		env["ENVVAULT_CHECK_TOKEN"] = "envvault://microsandbox/check"
	}
	name := fmt.Sprintf("envvault-codex-%d", time.Now().UnixNano())
	fmt.Println("Starting Codex's Microsandbox VM...")
	sb, err := m.CreateSandbox(ctx, name,
		m.WithImage(agentImage), m.WithRegistryAnonymous(),
		m.WithMemory(2048), m.WithCPUs(2), m.WithRootDisk(m.RootDisk.Managed(4096)),
		m.WithUser("root"), m.WithWorkdir("/workspace"), m.WithEnv(env),
		m.WithMounts(map[string]m.MountConfig{
			"/workspace":  m.Mount.Bind(repoDir, m.MountOptions{Owner: &m.MountOwner{UID: 1000, GID: 1000}, Nosuid: true, Nodev: true}),
			"/home/agent": m.Mount.Named(agentHomeVolume, m.MountOptions{Nosuid: true, Nodev: true}),
		}),
		m.WithNetwork(&m.NetworkConfig{
			DefaultEgress: m.PolicyActionDeny, DefaultIngress: m.PolicyActionDeny,
			Rules: []m.PolicyRule{
				m.Rule.AllowDNS(),
				{Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress, Destination: "host", Protocol: m.PolicyProtocolTCP, Port: strconv.Itoa(proxy.port())},
			},
		}),
	)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		resultErr = errors.Join(resultErr, sb.Stop(cleanup), sb.Close(), m.RemoveSandbox(cleanup, name))
	}()
	if err := sb.FS().Write(ctx, "/usr/local/share/ca-certificates/envvault-agent.crt", proxy.tls.publicPEM); err != nil {
		return err
	}
	if _, err := checkedRootShell(ctx, sb, "update-ca-certificates >/dev/null 2>&1 && mkdir -p /etc/envvault && touch "+agentCatalogPath+" && chmod 0644 "+agentCatalogPath+" && if [ \"$(stat -c %u /home/agent)\" != 1000 ]; then chown -hR 1000:1000 /home/agent; fi"); err != nil {
		return err
	}
	if err := sb.FS().WriteString(ctx, "/etc/envvault/gitconfig", "[credential \"https://github.com\"]\n\tuseHttpPath = true\n\thelper = /usr/local/bin/git-credential-envvault\n"); err != nil {
		return err
	}
	processes, err := startAgentProcessController(ctx, sb, policyPath, cancel)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, processes.Close()) }()
	catalog, err := startAgentCatalogController(ctx, sb, proxy, cancel)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, catalog.Close()) }()
	if _, err := checkedAgentShell(ctx, sb, "mkdir -p \"$CODEX_HOME\" && git config --global --add safe.directory /workspace"); err != nil {
		return err
	}
	if mode == "agent-check" {
		return checkAgent(ctx, sb, policyPath, policy, credentialCheck)
	}
	attach := func(command string, args ...string) error {
		code, err := sb.AttachWith(ctx, agentEntrypoint, append([]string{command}, args...), m.WithAttachCwd("/workspace"), m.WithAttachEnv(env))
		if err != nil {
			return err
		}
		if code == -1 || code == 130 {
			return errAgentInterrupted
		}
		if code != 0 {
			return fmt.Errorf("agent command exited with code %d", code)
		}
		return nil
	}
	if mode == "shell" {
		return attach("/bin/bash", "-l")
	}
	codex := "/usr/local/bin/codex"
	loginArgs := []string{"-c", `cli_auth_credentials_store="file"`, "login", "--device-auth"}
	if mode == "login" {
		return attach(codex, loginArgs...)
	}
	extra := args[1:]
	if len(extra) > 0 && extra[0] == "--" {
		extra = extra[1:]
	}
	infoOnly := len(extra) == 1 && (extra[0] == "--version" || extra[0] == "--help" || extra[0] == "-h")
	if !infoOnly {
		status, err := sb.Exec(ctx, agentEntrypoint, []string{codex, "-c", `cli_auth_credentials_store="file"`, "login", "status"})
		if err != nil {
			return err
		}
		if status.ExitCode() != 0 {
			fmt.Println("Sign in with the URL and device code shown below; Codex will open after login.")
			if err := attach(codex, loginArgs...); err != nil {
				return err
			}
		}
	}
	fmt.Printf("Workspace: /workspace (edits write to your Mac). Host rules: %s\n", policyPath)
	return attach(codex, append([]string{"--sandbox", "danger-full-access", "--ask-for-approval", "on-request", "-c", `cli_auth_credentials_store="file"`}, extra...)...)
}

func prepareAgentImage(ctx context.Context, exampleDir string, force bool) error {
	if !force {
		if _, err := m.Image.Get(ctx, agentImage); err == nil {
			return nil
		} else {
			var typed *m.Error
			if !errors.As(err, &typed) || typed.Kind != m.ErrImageNotFound {
				return err
			}
		}
	}
	fmt.Println("Preparing the Codex image (Docker is needed for this first build)...")
	build := exec.CommandContext(ctx, "docker", "build", "--platform", "linux/"+runtime.GOARCH, "-t", agentImage, exampleDir)
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		return fmt.Errorf("build Codex image: %w", err)
	}
	archive, err := os.CreateTemp("", "envvault-msb-agent-*.tar")
	if err != nil {
		return err
	}
	archive.Close()
	defer os.Remove(archive.Name())
	save := exec.CommandContext(ctx, "docker", "save", "--output", archive.Name(), agentImage)
	save.Stderr = os.Stderr
	if err := save.Run(); err != nil {
		return fmt.Errorf("export Codex image: %w", err)
	}
	if _, err := m.Image.Load(ctx, archive.Name(), agentImage); err != nil {
		return fmt.Errorf("import Codex image: %w", err)
	}
	fmt.Println("Codex image cached in Microsandbox.")
	return nil
}

func checkedAgentShell(ctx context.Context, sb *m.Sandbox, command string) (string, error) {
	out, err := sb.Exec(ctx, agentEntrypoint, []string{"/bin/sh", "-c", command}, m.WithExecTimeout(90*time.Second))
	if err != nil {
		return "", err
	}
	if out.ExitCode() != 0 {
		return "", fmt.Errorf("agent check failed with code %d (output withheld)", out.ExitCode())
	}
	return strings.TrimSpace(out.Stdout()), nil
}

func writeAgentPolicy(filename string, policy agentPolicy) error {
	if policy.EnvVaultScope == "" {
		policy.EnvVaultScope = "profiles"
	}
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filename+".new", append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(filename+".new", filename)
}

func checkAgent(ctx context.Context, sb *m.Sandbox, policyPath string, policy agentPolicy, credentialCheck *agentCredentialCheck) error {
	versions, err := checkedAgentShell(ctx, sb, "codex --version && go version && node --version && test -r /workspace/go.mod && test -w /workspace && test -w /home/agent")
	if err != nil {
		return err
	}
	fmt.Println(versions)
	fmt.Println("PASS: Codex, development tools, shared repository, and persistent home")
	boot, err := checkedAgentShell(ctx, sb, "cat /proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	request := "curl -sS --max-time 20 -o /dev/null -w '%{http_code}' https://example.com/"
	if _, err := checkedAgentShell(ctx, sb, request); err == nil {
		return errors.New("unlisted proxy destination was allowed")
	}
	allowed := policy
	allowed.HTTPSHosts = append(append([]string(nil), policy.HTTPSHosts...), "example.com")
	if err := writeAgentPolicy(policyPath, allowed); err != nil {
		return err
	}
	if status, err := checkedAgentShell(ctx, sb, request); err != nil || status != "200" {
		return fmt.Errorf("live allow check: %w", errors.Join(err, fmt.Errorf("unexpected status %q", status)))
	}
	if err := writeAgentPolicy(policyPath, policy); err != nil {
		return err
	}
	if _, err := checkedAgentShell(ctx, sb, request); err == nil {
		return errors.New("removed proxy destination was allowed")
	}
	fmt.Println("PASS: host policy updates block, allow, and block HTTPS without restarting")
	if _, err := checkedAgentShell(ctx, sb, "curl -fsS --max-time 4 --noproxy '*' https://example.com/ -o /dev/null"); err == nil {
		return errors.New("direct egress bypassed the host proxy")
	}
	fmt.Println("PASS: direct egress cannot bypass the host proxy")
	if err := checkAgentCredentials(ctx, sb, policyPath, policy, credentialCheck); err != nil {
		return err
	}
	if err := checkAgentGitHub(ctx, sb, credentialCheck); err != nil {
		return err
	}
	if err := checkAgentGit(ctx, sb, credentialCheck); err != nil {
		return err
	}
	if err := checkAgentProcesses(ctx, sb, policyPath, policy); err != nil {
		return err
	}
	if after, err := checkedAgentShell(ctx, sb, "cat /proc/sys/kernel/random/boot_id"); err != nil || after != boot {
		return errors.New("VM changed during policy checks")
	}
	if _, err := checkedAgentShell(ctx, sb, "cd /workspace && go test ./internal/envref"); err != nil {
		return fmt.Errorf("EnvVault package test: %w", err)
	}
	fmt.Println("PASS: the same VM stayed running; EnvVault's Go package test passed")
	return nil
}
