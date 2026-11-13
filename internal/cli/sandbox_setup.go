package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/config"
	msb "github.com/trknhr/envvault/internal/runtime/microsandbox"
)

func (a App) newSandboxSetupCommand(execution *commandExecution) *cobra.Command {
	var source string
	var force bool
	cmd := &cobra.Command{
		Use: "setup", Short: "Install the optional Microsandbox helper for this EnvVault version",
		Long: `Download the native helper matching this CLI version and verify its release SHA-256 checksum.
The helper is stored in EnvVault's private data directory; no checkout, Go compiler,
or PATH changes are needed. First launch prepares the runtime and Codex image
(Docker is required for image preparation). Existing home and policy are reused.

After upgrading EnvVault, run this command again or launch sandbox codex to install
the matching helper automatically. Development builds can install a trusted local
binary with --helper. --force downloads the matching release again to repair it.`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			workspace, err := a.sandboxWorkspace()
			if err != nil {
				failCommand(execution, cmd, err)
				return
			}
			manager, err := a.microsandboxManager(workspace)
			if err == nil {
				var binary string
				ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
				defer stop()
				binary, err = manager.Install(ctx, source, force)
				if err == nil {
					fmt.Fprintf(cmd.OutOrStdout(), "Microsandbox helper ready: %s\nLaunch from your project: envvault sandbox codex\n", binary)
					return
				}
			}
			failCommand(execution, cmd, clerr.New(clerr.RuntimeUnavailable, "Microsandbox setup failed: "+err.Error()))
		},
	}
	cmd.Flags().StringVar(&source, "helper", "", "Install an explicitly trusted local helper binary (for source builds)")
	cmd.Flags().BoolVar(&force, "force", false, "Download the matching release helper again")
	return cmd
}

func (a App) microsandboxManager(workspace string) (msb.Manager, error) {
	paths := a.paths
	if paths.DataDir == "" {
		var err error
		paths, err = config.DefaultPaths()
		if err != nil {
			return msb.Manager{}, err
		}
	}
	dir, err := filepath.Abs(filepath.Join(paths.DataDir, "microsandbox"))
	if err == nil {
		err = requireOutsideWorkspace(workspace, dir)
	}
	if err != nil {
		return msb.Manager{}, err
	}
	return msb.Manager{Dir: dir, Version: strings.TrimSpace(version), HTTP: a.sandboxHelperHTTP}, nil
}

// Resolve existing ancestors too: setup must reject a not-yet-created helper
// directory under a workspace or a symlink into it, before writing any files.
func requireOutsideWorkspace(workspace, target string) error {
	workspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		return err
	}
	ancestor := target
	var missing []string
	for {
		_, err = os.Lstat(ancestor)
		if !errors.Is(err, os.ErrNotExist) {
			break
		}
		missing = append(missing, filepath.Base(ancestor))
		ancestor = filepath.Dir(ancestor)
	}
	if err != nil {
		return err
	}
	ancestor, err = filepath.EvalSymlinks(ancestor)
	if err != nil {
		return err
	}
	for i := len(missing) - 1; i >= 0; i-- {
		ancestor = filepath.Join(ancestor, missing[i])
	}
	rel, err := filepath.Rel(workspace, ancestor)
	if err != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return clerr.New(clerr.RuntimeUnavailable, "Microsandbox helper and its data directory must be outside the shared workspace")
	}
	return nil
}

func (a App) managedMicrosandbox(ctx context.Context, workspace string) (string, error) {
	manager, err := a.microsandboxManager(workspace)
	if err != nil {
		return "", err
	}
	binary, err := manager.Resolve()
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return binary, err
	}
	// Legacy PATH helpers are accepted only for source builds with no managed
	// installation. Released CLIs always install their version-matched helper.
	if manager.Version == "dev" {
		if legacy, lookupErr := exec.LookPath(msb.Helper); lookupErr == nil {
			return legacy, nil
		}
	}
	return manager.Install(ctx, "", false)
}
