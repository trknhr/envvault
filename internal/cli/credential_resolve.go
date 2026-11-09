package cli

import (
	"bytes"
	"context"
	"io"

	"github.com/spf13/cobra"
	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/keyring"
)

func (a App) newCredentialResolveCommand(execution *commandExecution) *cobra.Command {
	return &cobra.Command{
		Use:   "resolve <envvault://credential>",
		Short: "Resolve a direct credential for a host-side secret consumer",
		Long: `Write one direct credential to standard output, without a newline.

Intended for host-side consumers such as sbx secret set --command. Output is a
real secret: never log it or run this command to inspect a credential. Terminal
output is refused. Empty values, control characters, and surrounding whitespace
are rejected because the consumer uses the value as an HTTP header credential.
Proxy /token and /base-url references are not supported.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			execution.exitCode = a.runCredentialResolve(cmd.Context(), args[0], cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
}

func (a App) runCredentialResolve(ctx context.Context, raw string, stdout, stderr io.Writer) int {
	ref, ok, err := envref.ParseValue(raw)
	if err != nil || !ok || ref.Part != envref.PartDefault {
		return exitError(stderr, clerr.New(clerr.ReferenceInvalid, "a direct envvault:// credential reference is required"))
	}
	if a.tokenOutputToTerminal() {
		return exitError(stderr, clerr.New(clerr.ConfigInvalid, "credential resolver output must be captured by a host-side consumer"))
	}
	if err := a.requireSecrets(); err != nil {
		return exitError(stderr, err)
	}
	value, err := a.secrets.Get(ctx, keyring.CredentialValue(ref.Profile))
	defer keyring.Zero(value)
	if err != nil {
		// Backend and output errors may contain secret material. Do not render them.
		return exitError(stderr, clerr.New(clerr.KeyringUnavailable, "credential could not be resolved"))
	}
	if len(value) == 0 || !bytes.Equal(value, bytes.TrimSpace(value)) || bytes.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return exitError(stderr, clerr.New(clerr.ConfigInvalid, "credential is not a non-empty HTTP header value without surrounding whitespace"))
	}
	n, err := stdout.Write(value)
	if err != nil || n != len(value) {
		return exitError(stderr, clerr.New(clerr.ConfigInvalid, "write credential to host-side consumer failed"))
	}
	return 0
}
