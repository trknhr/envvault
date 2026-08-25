package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

func (a App) newSandboxPluginCommand(execution *commandExecution) *cobra.Command {
	command := newCommandGroup(
		"plugin",
		"Serve external agent-sandbox integrations",
		"envvault: usage: envvault sandbox plugin serve [options]",
		execution,
	)
	command.AddCommand(a.newSandboxPluginServeCommand(execution))
	return command
}

func (a App) newSandboxPluginServeCommand(execution *commandExecution) *cobra.Command {
	options := sandboxPluginServeArgs{gatewayListen: "127.0.0.1:0"}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the experimental sandbox plugin protocol over stdio",
		Long: strings.TrimSpace(`Serve a versioned newline-delimited JSON protocol for a trusted sandbox control plane.

The control plane receives only temporary gateway capabilities and must keep
the plugin process stdin open until all sandbox leases have been closed. Raw
upstream credentials remain in EnvVault and its trusted gateway.`),
		Example: commandExamples(
			"envvault sandbox plugin serve",
			"envvault sandbox plugin serve --gateway-listen 0.0.0.0:0 --gateway-host host.docker.internal",
		),
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			execution.exitCode = a.runSandboxPluginServe(cmd.Context(), options, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&options.gatewayListen, "gateway-listen", options.gatewayListen, "Temporary data-plane gateway listen address (port must be 0)")
	cmd.Flags().StringVar(&options.gatewayHost, "gateway-host", "", "Gateway hostname or IP advertised to sandboxes")
	return cmd
}
