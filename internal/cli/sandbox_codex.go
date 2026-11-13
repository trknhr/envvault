package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/trknhr/envvault/internal/clerr"
)

func (a App) newSandboxCodexCommand(execution *commandExecution) *cobra.Command {
	cmd := &cobra.Command{
		Use: "codex [--] [Codex arguments]", Short: "Launch Codex in Microsandbox with the current directory as its workspace",
		Long: `Launch Codex in a Linux microVM with the current directory mounted read/write at /workspace.

The optional native helper is installed automatically on first launch. To
install it ahead of time, run:

  envvault sandbox setup

Then run envvault sandbox codex from any project directory. Codex arguments are
forwarded unchanged. Run the same command in multiple terminals for parallel
sessions. Terminals in the same workspace share its managed sandbox, sign-in,
caches, and conversation history. Other workspaces have separate writable state.
Use resume, resume --last, or resume <id> as with ordinary Codex. The VM shuts
down shortly after its last terminal exits; project history persists for the
next launch. Host network and EnvVault destination rules apply to every session.
The native helper stays separate from the core EnvVault binary.`,
		DisableFlagParsing: true,
		Example:            commandExamples("envvault sandbox codex", "envvault sandbox codex resume", "envvault sandbox codex resume --last", `envvault sandbox codex "Explain this project"`, "envvault sandbox codex --version"),
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
				_ = cmd.Help()
				return
			}
			execution.exitCode = a.runSandboxCodex(cmd.Context(), args, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	return cmd
}

func (a App) runSandboxCodex(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	workspace, err := a.sandboxWorkspace()
	if err != nil {
		return exitError(stderr, err)
	}
	workspace, err = filepath.EvalSymlinks(workspace)
	if err != nil {
		return exitError(stderr, clerr.New(clerr.ConfigInvalid, "sandbox workspace is unavailable"))
	}
	info, err := os.Stat(workspace)
	if err != nil || !info.IsDir() {
		return exitError(stderr, clerr.New(clerr.ConfigInvalid, "sandbox workspace must be a directory"))
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	helper, err := a.managedMicrosandbox(ctx, workspace)
	if err != nil {
		return exitError(stderr, clerr.New(clerr.RuntimeUnavailable, "Microsandbox helper unavailable; run envvault sandbox setup: "+err.Error()))
	}
	helper, err = filepath.Abs(helper)
	if err == nil {
		helper, err = filepath.EvalSymlinks(helper)
	}
	if err != nil {
		return exitError(stderr, clerr.New(clerr.RuntimeUnavailable, "Microsandbox helper is unavailable"))
	}
	if err := requireOutsideWorkspace(workspace, helper); err != nil {
		return exitError(stderr, err)
	}
	argv := []string{"codex", "--workspace", workspace}
	argv = append(append(argv, "--"), args...)
	child := exec.CommandContext(ctx, helper, argv...)
	child.Dir, child.Env = workspace, a.parentEnvironment()
	child.Stdin, child.Stdout, child.Stderr = a.commandStdin(), stdout, stderr
	// Give the helper time to stop/remove its VM when the host CLI is cancelled.
	child.Cancel = func() error { return child.Process.Signal(os.Interrupt) }
	child.WaitDelay = 35 * time.Second
	err = child.Run()
	if err == nil {
		return 0
	}
	if ctx.Err() != nil {
		return 130
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() >= 0 {
		return exit.ExitCode()
	}
	return exitError(stderr, clerr.New(clerr.RuntimeUnavailable, "Microsandbox launcher failed to start"))
}
