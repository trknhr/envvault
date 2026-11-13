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
	"strings"
	"syscall"
	"time"

	m "github.com/superradcompany/microsandbox/sdk/go"
)

const agentImage = "envvault-codex-msb:0.166.0-v4"

var errAgentInterrupted = errors.New("agent session interrupted")

func runAgent(args []string) (resultErr error) {
	options, err := parseAgentOptions(args)
	if err != nil {
		return err
	}
	stateDir, err := filepath.Abs(os.Getenv("MSB_HOME"))
	if err != nil {
		return err
	}
	if err := protectAgentVaultPath(stateDir, options.workspace); err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}
	stateDir, err = filepath.EvalSymlinks(stateDir)
	if err != nil {
		return err
	}
	if err := os.Setenv("MSB_HOME", stateDir); err != nil {
		return err
	}
	policyPath := filepath.Join(stateDir, "agent-policy.json")
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	defer func() {
		if ctx.Err() != nil {
			resultErr = errors.Join(resultErr, errAgentInterrupted)
		}
	}()
	switch options.mode {
	case "rules":
		policy, err := prepareAgentHost(ctx, stateDir, policyPath, "rules")
		if err != nil {
			return err
		}
		data, _ := json.MarshalIndent(policy, "", "  ")
		fmt.Printf("Host policy: %s\n%s\nWorkspace: %s -> /workspace (read/write)\n", policyPath, data, options.workspace)
		fmt.Println("Session storage: managed per workspace; parallel terminals share that project's sandbox and Codex history.")
		fmt.Println("Only gateway DNS and the host proxy are reachable directly. Each HTTPS request is checked against the listed hosts on port 443.")
		fmt.Println("Removed hosts' connections close within the 250ms polling interval, subject to scheduling. The proxy CA private key stays on the host.")
		fmt.Printf("Agent UID/GID: 1000:1000, no capabilities; live process/thread limit for this project's VM: %d. EnvVault credential values resolve on the host only.\n", policy.MaxProcesses)
		if len(policy.NativeAuthHosts) > 0 {
			fmt.Printf("Native authentication allowed for: %s. Native login credentials are readable in the project sandbox.\n", strings.Join(policy.NativeAuthHosts, ", "))
		}
		if policy.EnvVault {
			vault, err := defaultAgentVault(options.workspace)
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
	case "agent-setup":
		_, err := prepareAgentHost(ctx, stateDir, policyPath, options.mode)
		return err
	case "agent-check":
		return runStandaloneAgentCheck(ctx, stateDir, options.workspace, policyPath)
	}
	project, err := newAgentProject(stateDir, options.workspace)
	if err != nil {
		return err
	}
	digest, err := agentHelperDigest()
	if err != nil {
		return err
	}
	if options.mode == "agent-serve" {
		lock, err := inheritedAgentLock(project)
		if err != nil {
			return err
		}
		return serveAgentProject(ctx, project, digest, lock, func(lifetime context.Context) (agentSupervisorBackend, error) {
			if _, err := prepareAgentHost(lifetime, stateDir, policyPath, "codex"); err != nil {
				return nil, err
			}
			if err := removeAgentOrphan(lifetime, project); err != nil {
				return nil, err
			}
			return newAgentRuntime(lifetime, agentRuntimeConfig{workspace: project.Workspace, policyPath: policyPath, name: project.Sandbox(), volume: project.Volume()})
		}, agentIdleGrace)
	}
	lease, err := connectAgentLease(ctx, project, digest)
	if err != nil {
		return err
	}
	defer lease.Close()
	handle, err := m.GetSandbox(lease.ctx, lease.session.Sandbox)
	if err != nil {
		return err
	}
	sb, err := handle.Connect(lease.ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		resultErr = errors.Join(resultErr, sb.Detach(cleanup))
	}()
	err = runAgentTerminal(lease.ctx, sb, options, lease.session.Environment, project.loginLock())
	if lease.ctx.Err() != nil && ctx.Err() == nil {
		return errors.New("project sandbox supervision was lost; this terminal's session stopped")
	}
	return err
}

func runStandaloneAgentCheck(ctx context.Context, stateDir, workspace, policyPath string) (resultErr error) {
	if _, err := prepareAgentHost(ctx, stateDir, policyPath, "codex"); err != nil {
		return err
	}
	policy := agentPolicy{HTTPSHosts: []string{"proxy.golang.org", "sum.golang.org", "storage.googleapis.com", agentCheckHost, "api.github.com", "github.com"}, MaxProcesses: 512, EnvVault: true, EnvVaultScope: "profiles"}
	dir, err := os.MkdirTemp(stateDir, "policy-check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	policyPath = filepath.Join(dir, "policy.json")
	if err := writeAgentPolicy(policyPath, policy); err != nil {
		return err
	}
	name := fmt.Sprintf("envvault-agent-check-%d", time.Now().UnixNano())
	volume := name + "-home"
	r, err := newAgentRuntime(ctx, agentRuntimeConfig{workspace: workspace, policyPath: policyPath, name: name, volume: volume, check: true})
	if err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		resultErr = errors.Join(resultErr, r.Close(cleanup), m.RemoveVolume(cleanup, volume))
	}()
	return checkAgent(ctx, r.sb, policyPath, policy, r.credentialCheck)
}

func prepareAgentHost(ctx context.Context, stateDir, policyPath, mode string) (agentPolicy, error) {
	setup, err := acquireAgentSetup(ctx, stateDir)
	if err != nil {
		return agentPolicy{}, err
	}
	defer setup.Close()
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		data, err := agentAssets.ReadFile("agent-policy.json")
		if err != nil {
			return agentPolicy{}, err
		}
		if err := os.WriteFile(policyPath, data, 0600); err != nil {
			return agentPolicy{}, err
		}
	}
	policy, err := readAgentPolicy(policyPath)
	if err != nil || mode == "rules" {
		return policy, err
	}
	if _, err := m.EnsureRuntime(ctx, m.RuntimeConfig{}, m.InstallOptions{}); err != nil {
		return agentPolicy{}, err
	}
	if err := prepareAgentImage(ctx, mode == "agent-setup"); err != nil {
		return agentPolicy{}, err
	}
	return policy, nil
}

func prepareAgentImage(ctx context.Context, force bool) error {
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
	exampleDir, cleanup, err := agentBuildContext()
	if err != nil {
		return err
	}
	defer cleanup()
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
	fmt.Println("PASS: the same VM stayed running; workspace Go package test passed")
	return nil
}
