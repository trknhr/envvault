package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/sandboxplugin"
	"github.com/trknhr/envvault/internal/sandboxsession"
	sessionagentinfra "github.com/trknhr/envvault/internal/sandboxsession/agentinfra"
)

type sandboxExecArgs struct {
	runtime        string
	runtimeCommand string
	target         string
	envFiles       []string
	inlineEnv      []string
	nonInteractive bool
	command        []string
}

func cloneSandboxSessionRuntimes(in map[string]sandboxsession.Runtime) map[string]sandboxsession.Runtime {
	out := make(map[string]sandboxsession.Runtime, len(in))
	for name, runtime := range in {
		out[name] = runtime
	}
	return out
}

func (a App) runSandboxExec(ctx context.Context, options sandboxExecArgs, stdout, stderr io.Writer) int {
	fail := func(err error) int { fmt.Fprintln(stderr, err); return 1 }
	if options.target == "" || strings.HasPrefix(options.target, "-") || len(options.target) > 255 || strings.ContainsAny(options.target, "\x00\r\n") {
		return fail(clerr.New(clerr.ConfigInvalid, "--target must name an existing sandbox branch"))
	}
	runtime := a.sandboxSessionRuntimes[options.runtime]
	if options.runtimeCommand != "" {
		if options.runtime != "agent-infra" {
			return fail(clerr.New(clerr.RuntimeIncompatible, "--runtime-command currently supports only agent-infra"))
		}
		runtime = sessionagentinfra.Runtime{Executable: options.runtimeCommand}
	}
	if runtime == nil {
		return fail(clerr.New(clerr.RuntimeUnavailable, "sandbox session runtime is not configured"))
	}
	bindings, err := sandboxsession.ReadBindings(ctx, options.envFiles, options.inlineEnv)
	if err != nil {
		return fail(err)
	}
	if !options.nonInteractive && (!stdinIsTerminal() || !outputIsTerminal(stdout)) {
		return fail(clerr.New(clerr.ConfigInvalid, "sandbox exec requires a terminal; use --non-interactive for scripts"))
	}
	directory, err := a.sandboxWorkspace()
	if err != nil {
		return fail(err)
	}
	identity, err := a.detectProjectIdentity(ctx)
	if err != nil {
		return fail(err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(identity.Root)
	if err != nil {
		return fail(clerr.New(clerr.ProjectNotTrusted, "cannot resolve the host project root"))
	}
	ctx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stopSignals()
	prepared, err := runtime.Prepare(ctx, sandboxsession.Target{
		Reference: options.target, Directory: directory,
		Interactive: !options.nonInteractive, ParentEnv: a.parentEnvironment(),
	})
	if err != nil {
		return fail(err)
	}
	if prepared.Project.Root != canonicalRoot || prepared.Project.GitRemote != identity.GitRemote {
		return fail(clerr.New(clerr.ProjectNotTrusted, "runtime session does not match the current host project"))
	}
	broker := &sandboxplugin.Broker{
		Profiles: a.profiles, Secrets: a.secrets, Now: a.now,
		ListenAddress: prepared.Gateway.ListenAddress, AdvertiseHost: prepared.Gateway.AdvertiseHost,
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = broker.CloseAll(cleanupCtx)
	}()
	lease, err := broker.Open(ctx, sandboxplugin.OpenRequest{
		SandboxID: prepared.ID, Project: prepared.Project, Bindings: bindings,
	})
	if err != nil {
		return fail(err)
	}
	leaseCtx, cancel := context.WithDeadline(ctx, lease.ExpiresAt)
	defer cancel()
	commandDone := make(chan struct{})
	revoked := make(chan error, 1)
	go func() {
		select {
		case <-leaseCtx.Done():
		case <-commandDone:
		}
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		revoked <- broker.CloseAll(cleanupCtx)
	}()
	code, runErr := runtime.Run(leaseCtx, prepared, sandboxsession.Command{
		Args: options.command, Environment: lease.Environment, Stdin: a.stdin, Stdout: stdout, Stderr: stderr,
	})
	close(commandDone)
	cleanupErr := <-revoked
	if runErr != nil {
		return fail(runErr)
	}
	if cleanupErr != nil {
		return fail(clerr.New(clerr.CleanupFailed, "could not close sandbox session access"))
	}
	if leaseCtx.Err() != nil {
		return fail(clerr.New(clerr.RuntimeUnavailable, "sandbox session canceled or credential lease expired"))
	}
	return code
}
