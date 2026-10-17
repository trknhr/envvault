package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/transfer"
	"golang.org/x/term"
)

// PassphraseReader reads one passphrase without echo. The prompt is written to
// output. The caller clears the returned buffer.
type PassphraseReader func(output io.Writer, prompt string) ([]byte, error)

func terminalPassphraseReader(input *os.File) PassphraseReader {
	return func(output io.Writer, prompt string) ([]byte, error) {
		if input == nil || !term.IsTerminal(int(input.Fd())) {
			return nil, clerr.New(clerr.ConfigInvalid, "passphrase requires a terminal; use --passphrase-stdin")
		}
		if _, err := fmt.Fprint(output, prompt); err != nil {
			return nil, clerr.Wrap(clerr.ConfigInvalid, "write passphrase prompt", err)
		}
		value, err := term.ReadPassword(int(input.Fd()))
		_, newlineErr := fmt.Fprintln(output)
		if err != nil {
			keyring.Zero(value)
			return nil, clerr.Wrap(clerr.ConfigInvalid, "read passphrase from terminal", err)
		}
		if newlineErr != nil {
			keyring.Zero(value)
			return nil, clerr.Wrap(clerr.ConfigInvalid, "write passphrase prompt", newlineErr)
		}
		return value, nil
	}
}

func readPassphraseStdin(input io.Reader) ([]byte, error) {
	if input == nil {
		return nil, clerr.New(clerr.ConfigInvalid, "passphrase requires a terminal; use --passphrase-stdin")
	}
	buf := make([]byte, 0, 64)
	tmp := []byte{0}
	defer keyring.Zero(tmp)
	for {
		n, err := input.Read(tmp)
		if n == 1 {
			if tmp[0] == '\n' {
				break
			}
			if len(buf) >= transfer.MaxPassphraseLen {
				keyring.Zero(buf)
				return nil, clerr.New(clerr.ConfigInvalid, "passphrase is too long")
			}
			buf = append(buf, tmp[0])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			keyring.Zero(buf)
			return nil, clerr.Wrap(clerr.ConfigInvalid, "read passphrase", err)
		}
	}
	if len(buf) > 0 && buf[len(buf)-1] == '\r' {
		buf[len(buf)-1] = 0
		buf = buf[:len(buf)-1]
	}
	return buf, nil
}
