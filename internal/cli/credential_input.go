package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/trknhr/envvault/internal/clerr"
	"golang.org/x/term"
)

// CredentialReader reads one credential value without exposing it as a
// command-line argument. Implementations may write a prompt to output. The
// caller clears the returned byte slice after storing it.
type CredentialReader func(output io.Writer) ([]byte, error)

func terminalCredentialReader(input *os.File) CredentialReader {
	return func(output io.Writer) ([]byte, error) {
		if input == nil || !term.IsTerminal(int(input.Fd())) {
			return nil, clerr.New(clerr.ConfigInvalid, "interactive credential input requires a terminal; use envvault credential set <name> --value-stdin for piped input")
		}
		if _, err := fmt.Fprint(output, "Credential value: "); err != nil {
			return nil, clerr.Wrap(clerr.ConfigInvalid, "write credential prompt", err)
		}
		value, err := term.ReadPassword(int(input.Fd()))
		_, newlineErr := fmt.Fprintln(output)
		if err != nil {
			return nil, clerr.Wrap(clerr.ConfigInvalid, "read credential from terminal", err)
		}
		if newlineErr != nil {
			zero(value)
			return nil, clerr.Wrap(clerr.ConfigInvalid, "write credential prompt", newlineErr)
		}
		return value, nil
	}
}
