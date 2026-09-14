package cli

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/trknhr/envvault/internal/clerr"
)

func (a App) newSandboxExecCommand(execution *commandExecution) *cobra.Command {
	options := sandboxExecArgs{runtime: "agent-infra"}
	cmd := &cobra.Command{
		Use:   "exec [flags] -- <command>",
		Short: "Connect provider credentials to a process in an existing sandbox",
		Long: strings.TrimSpace(`Launch a fresh process in an existing external sandbox with temporary
EnvVault provider-proxy outputs. The external runtime owns the container,
workspace, terminal and clipboard; EnvVault owns credential access and revocation.

The first integration supports macOS, local Docker Desktop, branch-only
agent-infra sandboxes, and a session-capable agent-infra build. Stock 0.9.13
does not expose the required session interface. Select a local integration
build with --runtime-command; no private npm modules are imported.

Only envvault://profile/base-url and /token references are accepted. Every
profile requires both outputs. No raw credentials, automatic model-provider
configuration, MCP OAuth, tmux reattachment, or automatic lease renewal.
Exiting revokes access but does not stop or delete the existing container.
The connection is brokered, not network-enforced; native auth mounts remain.

Interactive terminal and image paste are enabled by default. For scripts,
use --non-interactive. Run this command from the host agent-infra project.`),
		Example: commandExamples(
			"envvault sandbox exec --runtime agent-infra --target clipboard-test --env-file .env.sandbox -- codex",
			"envvault sandbox exec --target clipboard-test --env API_URL=envvault://api/dev/base-url --env API_TOKEN=envvault://api/dev/token --non-interactive -- node test.js",
		),
		Args: func(cmd *cobra.Command, args []string) error {
			if cmd.ArgsLenAtDash() != 0 || len(args) == 0 {
				return clerr.New(clerr.ConfigInvalid, "sandbox exec requires -- child command")
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			options.command = append([]string(nil), args...)
			execution.exitCode = a.runSandboxExec(cmd.Context(), options, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&options.runtime, "runtime", options.runtime, "External sandbox runtime (agent-infra)")
	cmd.Flags().StringVar(&options.target, "target", "", "Existing sandbox branch (required)")
	cmd.Flags().StringVar(&options.runtimeCommand, "runtime-command", "", "Explicit agent-infra executable (not a shell command)")
	cmd.Flags().StringArrayVar(&options.envFiles, "env-file", nil, "Read provider-proxy references from a dotenv file (repeatable)")
	cmd.Flags().StringArrayVar(&options.inlineEnv, "env", nil, "Map NAME to a provider-proxy reference (repeatable; overrides files)")
	cmd.Flags().BoolVar(&options.nonInteractive, "non-interactive", false, "Disable terminal and clipboard for scripted commands")
	return cmd
}
