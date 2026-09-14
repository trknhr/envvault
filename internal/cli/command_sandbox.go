package cli

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/trknhr/envvault/internal/clerr"
)

func (a App) newSandboxCommand(execution *commandExecution) *cobra.Command {
	command := newCommandGroup(
		"sandbox",
		"Integrate EnvVault with experimental sandboxes",
		"envvault: usage: envvault sandbox <run|exec|plugin>",
		execution,
	)
	command.AddCommand(
		a.newSandboxRunCommand(execution),
		a.newSandboxExecCommand(execution),
		a.newSandboxPluginCommand(execution),
	)
	return command
}

func (a App) newSandboxRunCommand(execution *commandExecution) *cobra.Command {
	options := sandboxRunArgs{runtime: "docker"}
	cmd := &cobra.Command{
		Use:   "run [flags] -- <command>",
		Short: "Run a command in an experimental sandbox",
		Long: strings.TrimSpace(`Run a command in an experimental sandbox using existing EnvVault references.

Provider-proxy base-url and token references are converted to a temporary
gateway endpoint. A direct credential reference remains a non-secret,
late-bound handle only when a matching --outbound-profile is attached.
Other direct references are rejected unless --allow-materialized-secrets is
explicitly set.

Known agents such as Codex can attach a compatible provider-proxy profile
without an env file. Use --agent-auth native for isolated agent-owned login
state, --agent-auth with a profile to disambiguate proxy profiles, or
--no-agent-auth to disable automatic attachment.

Use --outbound-profile to keep a provider's original URL while EnvVault
injects its credential through a runtime-provided outbound proxy. Put the
profile's underlying credential reference in the application's normal API-key
environment variable. Use --all to attach every provider-proxy profile whose
project binding permits the current workspace. The Docker prototype relies on
the child process honoring HTTP(S)_PROXY; it does not block direct egress.`),
		Example: commandExamples(
			"envvault sandbox run --runtime docker --image node:22 --env-file .env -- npm test",
			"envvault sandbox run -it --runtime docker --image envvault-codex:local -- codex",
			"envvault sandbox run -it --agent-auth openai-codex/dev --image envvault-codex:local -- codex",
			"envvault sandbox run -it --agent-auth native --image envvault-codex:local -- codex login --device-auth",
			"envvault sandbox run -it --agent-auth native --outbound-profile tools-api/dev --env-file .env --image envvault-codex:local -- codex",
			"envvault sandbox run -it --agent-auth native --all --image envvault-codex:local -- codex",
			"envvault sandbox run --runtime docker --image node:22 --env APP_URL=envvault://api/dev/base-url -- node app.js",
		),
		Args: validateSandboxRunCommand,
		Run: func(cmd *cobra.Command, args []string) {
			if strings.TrimSpace(options.image) == "" {
				failCommand(execution, cmd, clerr.New(clerr.ConfigInvalid, "--image is required"))
				return
			}
			options.command = append([]string(nil), args...)
			execution.exitCode = a.runSandbox(cmd.Context(), options, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&options.runtime, "runtime", options.runtime, "Sandbox runtime")
	cmd.Flags().StringVar(&options.image, "image", "", "Container image")
	cmd.Flags().StringArrayVar(&options.envFiles, "env-file", nil, "Read KEY=VALUE entries from a dotenv file (repeatable)")
	cmd.Flags().StringArrayVar(&options.inlineEnv, "env", nil, "Add KEY=VALUE to the sandbox environment (repeatable)")
	cmd.Flags().StringArrayVar(&options.publish, "publish", nil, "Publish a container port on random host loopback (repeatable)")
	cmd.Flags().BoolVarP(&options.interactive, "interactive", "i", false, "Keep the sandbox standard input open")
	cmd.Flags().BoolVarP(&options.tty, "tty", "t", false, "Allocate a pseudo-TTY")
	cmd.Flags().StringVar(&options.agentAuth, "agent-auth", "", "Agent auth mode 'native' or a brokered provider-proxy profile")
	cmd.Flags().StringVar(&options.agentAuthProfile, "agent-auth-profile", "", "Isolated native agent auth profile (default \"default\")")
	cmd.Flags().BoolVar(&options.noAgentAuth, "no-agent-auth", false, "Disable automatic agent authentication")
	cmd.Flags().StringArrayVar(&options.outboundProfiles, "outbound-profile", nil, "Broker a provider profile at its original outbound URL (repeatable)")
	cmd.Flags().BoolVar(&options.allOutboundProfiles, "all", false, "Broker all provider-proxy profiles allowed for the current project")
	cmd.Flags().BoolVar(&options.allowMaterializedSecrets, "allow-materialized-secrets", false, "Allow direct credentials in the sandbox environment")
	return cmd
}

func validateSandboxRunCommand(cmd *cobra.Command, args []string) error {
	dash := cmd.ArgsLenAtDash()
	if dash < 0 {
		return clerr.New(clerr.ConfigInvalid, "sandbox run requires -- child command")
	}
	if dash != 0 {
		return clerr.New(clerr.ConfigInvalid, "sandbox run arguments must be followed by -- child command")
	}
	if len(args) == 0 {
		return clerr.New(clerr.ConfigInvalid, "sandbox child command is required")
	}
	return nil
}
