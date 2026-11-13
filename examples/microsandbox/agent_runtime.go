package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	m "github.com/superradcompany/microsandbox/sdk/go"
)

type agentRuntimeConfig struct {
	workspace, policyPath, name, volume string
	check                               bool
}

type agentRuntime struct {
	sb              *m.Sandbox
	env             map[string]string
	name            string
	cancel          context.CancelFunc
	proxy           *agentProxy
	processes       *agentProcessController
	catalog         *agentProcessController
	credentialCheck *agentCredentialCheck
	closeOnce       sync.Once
	closeErr        error
	done            <-chan struct{}
}

func newAgentRuntime(parent context.Context, cfg agentRuntimeConfig) (result *agentRuntime, resultErr error) {
	ctx, cancel := context.WithCancel(parent)
	r := &agentRuntime{name: cfg.name, cancel: cancel, done: ctx.Done()}
	defer func() {
		if resultErr != nil {
			cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
			defer stop()
			resultErr = errors.Join(resultErr, r.Close(cleanup))
		}
	}()
	policy, err := readAgentPolicy(cfg.policyPath)
	if err != nil {
		return nil, err
	}
	if _, err := m.GetVolume(ctx, cfg.volume); err != nil {
		var typed *m.Error
		if !errors.As(err, &typed) || typed.Kind != m.ErrVolumeNotFound {
			return nil, err
		}
		if _, err := m.CreateVolume(ctx, cfg.volume, m.WithVolumeKind(m.VolumeKindDisk), m.WithVolumeSize(8192)); err != nil {
			return nil, err
		}
	}
	if cfg.check {
		r.proxy, r.credentialCheck, err = startAgentCheckProxy(cfg.policyPath)
	} else {
		r.proxy, err = startAgentProxy(cfg.policyPath, cfg.workspace)
	}
	if err != nil {
		return nil, err
	}
	proxyURL := fmt.Sprintf("http://host.microsandbox.internal:%d", r.proxy.port())
	r.env = map[string]string{
		"HOME": "/home/agent", "CODEX_HOME": "/home/agent/.codex",
		"GOPATH": "/home/agent/go", "GOCACHE": "/home/agent/.cache/go-build",
		"HTTP_PROXY": proxyURL, "HTTPS_PROXY": proxyURL,
		"http_proxy": proxyURL, "https_proxy": proxyURL, "NO_PROXY": "", "no_proxy": "",
		"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TERM": "xterm-256color", "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
		"CODEX_CA_CERTIFICATE":      "/etc/ssl/certs/ca-certificates.crt",
		"NODE_EXTRA_CA_CERTS":       "/usr/local/share/ca-certificates/envvault-agent.crt",
		"ENVVAULT_CREDENTIALS_FILE": agentCatalogPath, "GIT_CONFIG_SYSTEM": "/etc/envvault/gitconfig",
	}
	for _, binding := range policy.Credentials {
		r.env[binding.Environment] = binding.Reference
	}
	if cfg.check {
		r.env["ENVVAULT_CHECK_TOKEN"] = "envvault://microsandbox/check"
	}
	r.sb, err = m.CreateSandbox(ctx, cfg.name,
		m.WithImage(agentImage), m.WithRegistryAnonymous(),
		m.WithMemory(2048), m.WithCPUs(2), m.WithRootDisk(m.RootDisk.Managed(4096)),
		m.WithUser("root"), m.WithWorkdir("/workspace"), m.WithEnv(r.env),
		m.WithMounts(map[string]m.MountConfig{
			"/workspace":  m.Mount.Bind(cfg.workspace, m.MountOptions{Owner: &m.MountOwner{UID: 1000, GID: 1000}, Nosuid: true, Nodev: true}),
			"/home/agent": m.Mount.Named(cfg.volume, m.MountOptions{Nosuid: true, Nodev: true}),
		}),
		m.WithNetwork(&m.NetworkConfig{
			DefaultEgress: m.PolicyActionDeny, DefaultIngress: m.PolicyActionDeny,
			Rules: []m.PolicyRule{m.Rule.AllowDNS(),
				{Action: m.PolicyActionAllow, Direction: m.PolicyDirectionEgress, Destination: "host", Protocol: m.PolicyProtocolTCP, Port: strconv.Itoa(r.proxy.port())}},
		}),
	)
	if err != nil {
		return nil, err
	}
	if err := r.sb.FS().Write(ctx, "/usr/local/share/ca-certificates/envvault-agent.crt", r.proxy.tls.publicPEM); err != nil {
		return nil, err
	}
	if _, err := checkedRootShell(ctx, r.sb, "update-ca-certificates >/dev/null 2>&1 && mkdir -p /etc/envvault && touch "+agentCatalogPath+" && chmod 0644 "+agentCatalogPath+" && if [ \"$(stat -c %u /home/agent)\" != 1000 ]; then chown -hR 1000:1000 /home/agent; fi"); err != nil {
		return nil, err
	}
	if err := r.sb.FS().WriteString(ctx, "/etc/envvault/gitconfig", "[credential \"https://github.com\"]\n\tuseHttpPath = true\n\thelper = /usr/local/bin/git-credential-envvault\n"); err != nil {
		return nil, err
	}
	r.processes, err = startAgentProcessController(ctx, r.sb, cfg.policyPath, cancel)
	if err != nil {
		return nil, err
	}
	r.catalog, err = startAgentCatalogController(ctx, r.sb, r.proxy, cancel)
	if err != nil {
		return nil, err
	}
	if _, err := checkedAgentShell(ctx, r.sb, "mkdir -p \"$CODEX_HOME\" && git config --global --replace-all safe.directory /workspace"); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *agentRuntime) Close(ctx context.Context) error {
	r.closeOnce.Do(func() {
		r.cancel()
		if r.catalog != nil {
			r.closeErr = errors.Join(r.closeErr, r.catalog.Close())
		}
		if r.processes != nil {
			r.closeErr = errors.Join(r.closeErr, r.processes.Close())
		}
		if r.proxy != nil {
			r.closeErr = errors.Join(r.closeErr, r.proxy.Close())
		}
		if r.credentialCheck != nil {
			r.credentialCheck.origin.Close()
		}
		if r.sb != nil {
			// Destroy escalates to forceful termination after the grace interval.
			// Detach releases this handle without a second unbounded destructor.
			r.closeErr = errors.Join(r.closeErr, r.sb.Destroy(ctx, m.WithDestroyTimeout(10*time.Second)), r.sb.Detach(ctx))
		}
	})
	return r.closeErr
}

func (r *agentRuntime) descriptor(workspace, digest string) agentSession {
	return agentSession{Protocol: agentSupervisorProtocol, Workspace: workspace, Helper: digest, Sandbox: r.name, Environment: r.env}
}

func (r *agentRuntime) Done() <-chan struct{} { return r.done }

func runAgentTerminal(ctx context.Context, sb *m.Sandbox, options agentOptions, env map[string]string, loginLock string) error {
	attach := func(command string, args ...string) error {
		code, err := sb.AttachWith(ctx, agentEntrypoint, append([]string{command}, args...), m.WithAttachCwd("/workspace"), m.WithAttachEnv(env))
		if err != nil {
			return err
		}
		if code == -1 || code == 130 {
			return errAgentInterrupted
		}
		if code != 0 {
			return &agentExitError{code: code}
		}
		return nil
	}
	if options.mode == "shell" {
		return attach("/bin/bash", "-l")
	}
	const codex = "/usr/local/bin/codex"
	loginArgs := []string{"-c", `cli_auth_credentials_store="file"`, "login", "--device-auth"}
	if options.mode == "login" {
		lock, err := waitAgentLock(ctx, loginLock)
		if err != nil {
			return err
		}
		defer lock.Close()
		return attach(codex, loginArgs...)
	}
	if codexNeedsLogin(options.args) {
		if err := func() error {
			lock, err := waitAgentLock(ctx, loginLock)
			if err != nil {
				return err
			}
			defer lock.Close()
			status, err := sb.Exec(ctx, agentEntrypoint, []string{codex, "-c", `cli_auth_credentials_store="file"`, "login", "status"})
			if err != nil {
				return err
			}
			if status.ExitCode() != 0 {
				fmt.Println("Sign in with the URL and device code shown below; Codex will open after login.")
				return attach(codex, loginArgs...)
			}
			return nil
		}(); err != nil {
			return err
		}
	}
	return attach(codex, append([]string{"--sandbox", "danger-full-access", "--ask-for-approval", "on-request", "-c", `cli_auth_credentials_store="file"`}, options.args...)...)
}

func codexNeedsLogin(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if arg == "--help" || arg == "-h" || arg == "--version" || arg == "-V" {
			return false
		}
	}
	return len(args) == 0 || args[0] != "login" && args[0] != "logout" && args[0] != "completion"
}

type agentExitError struct{ code int }

func (e *agentExitError) Error() string {
	return fmt.Sprintf("agent command exited with code %d", e.code)
}

// Do not reuse a VM whose supervisor died: its proxy and policy controllers no
// longer exist. Terminate the exact old sandbox before reattaching its disk.
func removeAgentOrphan(ctx context.Context, project agentProject) error {
	handle, err := m.GetSandbox(ctx, project.Sandbox())
	if err != nil {
		var typed *m.Error
		if errors.As(err, &typed) && typed.Kind == m.ErrSandboxNotFound {
			return nil
		}
		return err
	}
	return handle.Destroy(ctx, m.WithDestroyForce())
}

func agentLogError(err error) string {
	// Credential backends already redact their errors; avoid propagating arbitrary
	// native runtime diagnostics over the control socket or terminal connection.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "project sandbox startup was cancelled"
	}
	return "project sandbox is unavailable; inspect its private supervisor log"
}
