package cli

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/transfer"
)

func (a App) newExportCommand(execution *commandExecution) *cobra.Command {
	var passphraseStdin bool
	cmd := &cobra.Command{
		Use:   "export <file>",
		Short: "Export credentials and profiles to an encrypted file",
		Long: strings.TrimSpace(`
Write credential values and profile configuration to one encrypted file.

The passphrase is prompted twice with echo disabled, or read as a single stdin
line with --passphrase-stdin. It is never accepted as a flag value.

The file holds credential values and profiles. It does not include the
installation id, Talos signing keys, or profile parent keys. Direct credentials
and inject or provider-proxy profiles work on another initialized machine.
Process and browser profiles are copied as policy, but issuing leased tokens
still requires parent keys created on that machine.

The file is written with mode 0600.`),
		Example: commandExamples(
			"envvault export secrets.envault",
			"envvault export secrets.envault --passphrase-stdin",
		),
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			execution.exitCode = a.runExport(cmd.Context(), args[0], passphraseStdin, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().BoolVar(&passphraseStdin, "passphrase-stdin", false, "Read one passphrase line from stdin instead of prompting")
	return cmd
}

func (a App) newImportCommand(execution *commandExecution) *cobra.Command {
	var passphraseStdin bool
	var overwrite bool
	cmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Import credentials and profiles from an encrypted file",
		Long: strings.TrimSpace(`
Read an encrypted export file and store its credentials in the OS credential store.

Profile configuration is merged into the local config. Existing credential and
profile names are left unchanged unless --overwrite is set. The destination
must already be initialized with envvault init.

A wrong passphrase and a tampered ciphertext produce different errors. Secret
values are not printed. The passphrase is prompted with echo disabled, or read
as a single stdin line with --passphrase-stdin. It is never accepted as a flag
value.`),
		Example: commandExamples(
			"envvault import secrets.envault",
			"envvault import secrets.envault --overwrite",
			"envvault import secrets.envault --passphrase-stdin",
		),
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			execution.exitCode = a.runImport(cmd.Context(), args[0], passphraseStdin, overwrite, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().BoolVar(&passphraseStdin, "passphrase-stdin", false, "Read one passphrase line from stdin instead of prompting")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Replace existing credentials and profiles with the same names")
	return cmd
}

func (a App) runExport(ctx context.Context, path string, passphraseStdin bool, stdout, stderr io.Writer) int {
	if err := a.requireSecrets(); err != nil {
		return exitError(stderr, err)
	}
	passphrase, err := a.readExportPassphrase(passphraseStdin, stderr)
	if err != nil {
		return exitError(stderr, err)
	}
	defer keyring.Zero(passphrase)

	cfg, err := config.Load(a.paths.ConfigFile)
	if err != nil {
		if configFileMissing(err) {
			return exitError(stderr, clerr.New(clerr.ConfigInvalid, "nothing to export"))
		}
		return exitError(stderr, err)
	}
	bundle, err := transfer.Collect(ctx, a.secrets, cfg)
	if err != nil {
		return exitError(stderr, err)
	}
	defer bundle.Zero()
	sealed, err := transfer.Seal(bundle, passphrase, a.exportKDF)
	if err != nil {
		return exitError(stderr, err)
	}
	defer keyring.Zero(sealed)
	if err := transfer.WritePrivateFile(path, sealed); err != nil {
		return exitError(stderr, err)
	}
	if err := writeNameLines(stdout, "exported credential", credentialNamesOf(bundle)); err != nil {
		return exitError(stderr, err)
	}
	if err := writeNameLines(stdout, "exported profile", profileNamesOf(bundle)); err != nil {
		return exitError(stderr, err)
	}
	return 0
}

func (a App) runImport(ctx context.Context, path string, passphraseStdin, overwrite bool, stdout, stderr io.Writer) int {
	if err := a.requireSecrets(); err != nil {
		return exitError(stderr, err)
	}
	passphrase, err := a.readImportPassphrase(passphraseStdin, stderr)
	if err != nil {
		return exitError(stderr, err)
	}
	defer keyring.Zero(passphrase)

	cfg, err := config.Load(a.paths.ConfigFile)
	if err != nil {
		if configFileMissing(err) {
			return exitError(stderr, clerr.New(clerr.ConfigInvalid, "run envvault init before import"))
		}
		return exitError(stderr, err)
	}
	file, err := transfer.ReadFile(path)
	if err != nil {
		return exitError(stderr, err)
	}
	defer keyring.Zero(file)
	bundle, err := transfer.Open(passphrase, file)
	if err != nil {
		return exitError(stderr, err)
	}
	defer bundle.Zero()
	result, err := transfer.Apply(ctx, a.secrets, cfg, bundle, overwrite, a.saveConfigFile)
	if err != nil {
		return exitError(stderr, err)
	}
	if err := writeImportResult(stdout, result); err != nil {
		return exitError(stderr, err)
	}
	return 0
}

func (a App) saveConfigFile(cfg config.File) error {
	if a.configSaver != nil {
		return a.configSaver(a.paths.ConfigFile, cfg)
	}
	return config.Save(a.paths.ConfigFile, cfg)
}

func (a App) readExportPassphrase(fromStdin bool, stderr io.Writer) ([]byte, error) {
	if fromStdin {
		return readPassphraseStdin(a.commandStdin())
	}
	if a.passphraseReader == nil {
		return nil, clerr.New(clerr.ConfigInvalid, "interactive passphrase input unavailable; use --passphrase-stdin")
	}
	firstRaw, err := a.passphraseReader(stderr, "Export passphrase: ")
	if err != nil {
		return nil, err
	}
	first := append([]byte(nil), firstRaw...)
	keyring.Zero(firstRaw)
	secondRaw, err := a.passphraseReader(stderr, "Confirm export passphrase: ")
	if err != nil {
		keyring.Zero(first)
		return nil, err
	}
	second := append([]byte(nil), secondRaw...)
	keyring.Zero(secondRaw)
	defer keyring.Zero(second)
	if subtle.ConstantTimeCompare(first, second) != 1 {
		keyring.Zero(first)
		return nil, clerr.New(clerr.ConfigInvalid, "passphrases do not match")
	}
	return first, nil
}

func (a App) readImportPassphrase(fromStdin bool, stderr io.Writer) ([]byte, error) {
	if fromStdin {
		return readPassphraseStdin(a.commandStdin())
	}
	if a.passphraseReader == nil {
		return nil, clerr.New(clerr.ConfigInvalid, "interactive passphrase input unavailable; use --passphrase-stdin")
	}
	raw, err := a.passphraseReader(stderr, "Import passphrase: ")
	if err != nil {
		return nil, err
	}
	passphrase := append([]byte(nil), raw...)
	keyring.Zero(raw)
	return passphrase, nil
}

func credentialNamesOf(bundle transfer.Bundle) []string {
	names := make([]string, 0, len(bundle.Credentials))
	for _, credential := range bundle.Credentials {
		names = append(names, credential.Name)
	}
	return names
}

func profileNamesOf(bundle transfer.Bundle) []string {
	names := make([]string, 0, len(bundle.Profiles))
	for name := range bundle.Profiles {
		names = append(names, name)
	}
	return names
}

func writeImportResult(stdout io.Writer, result transfer.Result) error {
	groups := []struct {
		prefix string
		names  []string
	}{
		{prefix: "imported credential", names: result.ImportedCredentials},
		{prefix: "replaced credential", names: result.ReplacedCredentials},
		{prefix: "skipped credential", names: result.SkippedCredentials},
		{prefix: "imported profile", names: result.ImportedProfiles},
		{prefix: "replaced profile", names: result.ReplacedProfiles},
		{prefix: "skipped profile", names: result.SkippedProfiles},
	}
	for _, group := range groups {
		if err := writeNameLines(stdout, group.prefix, group.names); err != nil {
			return err
		}
	}
	return nil
}

func writeNameLines(stdout io.Writer, prefix string, names []string) error {
	sorted := append([]string(nil), names...)
	slices.Sort(sorted)
	for _, name := range sorted {
		if _, err := fmt.Fprintf(stdout, "%s %s\n", prefix, name); err != nil {
			return clerr.Wrap(clerr.ConfigInvalid, "write export result", err)
		}
	}
	return nil
}

func configFileMissing(err error) bool {
	var envvaultErr *clerr.Error
	if !errors.As(err, &envvaultErr) || envvaultErr.Err == nil {
		return false
	}
	return os.IsNotExist(envvaultErr.Err)
}
