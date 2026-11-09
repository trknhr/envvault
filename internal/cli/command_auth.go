package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/trknhr/envvault/internal/authstate"
	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/keyring"
)

func (a App) authStore() authstate.Store {
	return authstate.Store{Dir: filepath.Join(a.paths.DataDir, "auth-profiles"), Keys: a.secrets}
}

func (a App) newAuthCommand(execution *commandExecution) *cobra.Command {
	root := &cobra.Command{Use: "auth", Short: "Manage host-only structured authentication profiles"}
	var file, format, provider, tokenField, expiresField, refreshField, clientID string
	var overwrite bool
	importCmd := &cobra.Command{Use: "import <name>", Short: "Encrypt a JSON or YAML authentication document on the host", Args: cobra.ExactArgs(1), Run: func(cmd *cobra.Command, args []string) {
		if format == "" {
			switch strings.ToLower(filepath.Ext(file)) {
			case ".yaml", ".yml":
				format = "yaml"
			default:
				format = "json"
			}
		}
		metadata := authstate.Metadata{Name: args[0], Provider: provider, Format: format, TokenField: tokenField, ExpiresField: expiresField, RefreshField: refreshField, ClientID: clientID}
		body, err := a.readAuthDocument(file)
		if err == nil {
			defer keyring.Zero(body)
			var canonical []byte
			canonical, err = authstate.Parse(body, format)
			if err == nil {
				defer keyring.Zero(canonical)
				err = a.saveAuth(cmd.Context(), metadata, canonical, overwrite)
			}
		}
		if err != nil {
			execution.exitCode = exitError(cmd.ErrOrStderr(), authCLIError(err))
			return
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Stored host authentication profile %s\nReference: envvault://%s\n", metadata.Name, metadata.Name)
	}}
	importCmd.Flags().StringVar(&file, "file", "", "Authentication file, or - for stdin")
	importCmd.Flags().StringVar(&format, "format", "", "json or yaml (defaults from filename)")
	importCmd.Flags().StringVar(&provider, "provider", "generic", "generic or github")
	importCmd.Flags().StringVar(&tokenField, "token-field", "/access_token", "Host-only JSON pointer selecting the access token")
	importCmd.Flags().StringVar(&expiresField, "expires-field", "", "JSON pointer selecting RFC3339 or Unix expiry")
	importCmd.Flags().StringVar(&refreshField, "refresh-field", "", "JSON pointer selecting the refresh token (GitHub)")
	importCmd.Flags().StringVar(&clientID, "client-id", "", "Public OAuth client ID for GitHub refresh")
	importCmd.Flags().BoolVar(&overwrite, "overwrite", false, "Replace an existing authentication profile")
	var loginName, loginClientID string
	var scopes []string
	login := &cobra.Command{Use: "login github", Short: "Sign in once on the host for authorized sandboxes", Args: cobra.ExactArgs(1), Run: func(cmd *cobra.Command, args []string) {
		if args[0] != "github" || !authstate.ValidName(loginName) {
			execution.exitCode = exitError(cmd.ErrOrStderr(), authCLIError(errors.New("use auth login github --name <profile>")))
			return
		}
		if err := a.checkAuthName(loginName, true); err != nil {
			execution.exitCode = exitError(cmd.ErrOrStderr(), authCLIError(err))
			return
		}
		metadata := authstate.Metadata{Name: loginName, Provider: "github", Format: "json", TokenField: "/access_token", ClientID: loginClientID, Scopes: scopes}
		var document []byte
		var err error
		if loginClientID == "" {
			document, err = a.loginGitHubCLI(cmd.Context(), scopes, cmd.ErrOrStderr())
		} else {
			github := authstate.GitHub{HTTP: a.authHTTP, Now: a.now}
			var device authstate.Device
			device, err = github.Begin(cmd.Context(), loginClientID, scopes)
			if err == nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Open %s and enter code %s\n", device.VerificationURL, device.UserCode)
				document, err = github.Wait(cmd.Context(), loginClientID, device)
			}
		}
		defer keyring.Zero(document)
		if err == nil {
			if _, fieldErr := authstate.Field(document, "/expires_at"); fieldErr == nil {
				metadata.ExpiresField = "/expires_at"
			}
			if _, fieldErr := authstate.Field(document, "/refresh_token"); fieldErr == nil {
				metadata.RefreshField = "/refresh_token"
			}
			err = a.saveAuth(cmd.Context(), metadata, document, true)
		}
		if err != nil {
			execution.exitCode = exitError(cmd.ErrOrStderr(), authCLIError(err))
			return
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Host login saved as %s\nReference: envvault://%s\n", loginName, loginName)
		if loginClientID == "" {
			fmt.Fprintln(cmd.OutOrStdout(), "Stored the current gh token. Automatic OAuth refresh requires a login with --client-id and a refresh-capable GitHub app.")
		}
	}}
	login.Flags().StringVar(&loginName, "name", "", "Authentication profile name")
	login.Flags().StringVar(&loginClientID, "client-id", os.Getenv("ENVVAULT_GITHUB_CLIENT_ID"), "Own GitHub OAuth app client ID; otherwise use an isolated host gh login")
	login.Flags().StringArrayVar(&scopes, "scope", nil, "OAuth scope (repeatable)")
	list := &cobra.Command{Use: "list", Short: "List public authentication metadata", Args: cobra.NoArgs, Run: func(cmd *cobra.Command, _ []string) {
		execution.exitCode = a.authList(cmd.Context(), "", cmd.OutOrStdout(), cmd.ErrOrStderr())
	}}
	status := &cobra.Command{Use: "status <name>", Short: "Inspect authentication metadata without displaying credentials", Args: cobra.ExactArgs(1), Run: func(cmd *cobra.Command, args []string) {
		execution.exitCode = a.authList(cmd.Context(), args[0], cmd.OutOrStdout(), cmd.ErrOrStderr())
	}}
	logout := &cobra.Command{Use: "logout <name>", Short: "Remove local host authentication and revoke its broker access", Long: "Remove the local host profile and its encryption key. This does not revoke the provider's upstream token or grant.", Args: cobra.ExactArgs(1), Run: func(cmd *cobra.Command, args []string) {
		err := a.authStore().WithLock(cmd.Context(), "registry", func() error {
			cfg, err := config.Load(a.paths.ConfigFile)
			if err != nil {
				return err
			}
			id, ok := cfg.AuthProfiles[args[0]]
			if !ok {
				return errors.New("authentication profile not found")
			}
			if err := a.authStore().Delete(cmd.Context(), id); err != nil {
				return err
			}
			delete(cfg.AuthProfiles, args[0])
			return a.saveAuthConfig(cfg)
		})
		if err != nil {
			execution.exitCode = exitError(cmd.ErrOrStderr(), authCLIError(err))
			return
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Removed host authentication profile %s\n", args[0])
	}}
	root.AddCommand(importCmd, login, list, status, logout)
	return root
}

func authCLIError(err error) error {
	return clerr.New(clerr.ConfigInvalid, "host authentication: "+err.Error())
}

func (a App) readAuthDocument(file string) ([]byte, error) {
	var input io.Reader
	if file == "-" {
		input = a.commandStdin()
	} else {
		info, err := os.Lstat(file)
		if err != nil || !info.Mode().IsRegular() || info.Size() > authstate.MaxDocumentBytes {
			return nil, errors.New("authentication source must be a bounded regular file")
		}
		f, err := os.Open(file)
		if err != nil {
			return nil, errors.New("authentication source unavailable")
		}
		defer f.Close()
		input = f
	}
	body, err := io.ReadAll(io.LimitReader(input, authstate.MaxDocumentBytes+1))
	if err != nil || len(body) > authstate.MaxDocumentBytes {
		keyring.Zero(body)
		return nil, errors.New("authentication document exceeds size limit")
	}
	return body, nil
}

func (a App) checkAuthName(name string, overwrite bool) error {
	if !authstate.ValidName(name) {
		return errors.New("invalid authentication profile name")
	}
	cfg, err := config.LoadOrDefault(a.paths.ConfigFile)
	if err != nil {
		return errors.New("configuration unavailable")
	}
	for _, existing := range cfg.CredentialNames() {
		if existing == name {
			return errors.New("name belongs to an existing opaque credential")
		}
	}
	if _, exists := cfg.AuthProfiles[name]; exists && !overwrite {
		return errors.New("authentication profile exists; use --overwrite")
	}
	return nil
}

func (a App) saveAuthConfig(cfg config.File) error {
	save := a.configSaver
	if save == nil {
		save = config.Save
	}
	if err := save(a.paths.ConfigFile, cfg); err != nil {
		return errors.New("authentication configuration could not be saved")
	}
	return nil
}

func (a App) saveAuth(ctx context.Context, metadata authstate.Metadata, document []byte, overwrite bool) error {
	if err := metadata.Validate(); err != nil {
		return err
	}
	return a.authStore().WithLock(ctx, "registry", func() error {
		if err := a.checkAuthName(metadata.Name, overwrite); err != nil {
			return err
		}
		cfg, err := config.LoadOrDefault(a.paths.ConfigFile)
		if err != nil {
			return errors.New("configuration unavailable")
		}
		var previous authstate.Record
		if id, exists := cfg.AuthProfiles[metadata.Name]; exists {
			previous, err = a.authStore().Read(ctx, id)
			if err != nil {
				return err
			}
			defer previous.Zero()
			metadata.ID = id
		}
		metadata, err = a.authStore().Put(ctx, metadata, document)
		if err != nil {
			return err
		}
		if cfg.AuthProfiles == nil {
			cfg.AuthProfiles = map[string]string{}
		}
		cfg.AuthProfiles[metadata.Name] = metadata.ID
		cfg.Version = 2
		if err := a.saveAuthConfig(cfg); err != nil {
			if previous.Metadata.ID == "" {
				_ = a.authStore().Delete(context.WithoutCancel(ctx), metadata.ID)
			} else {
				_, _ = a.authStore().Put(context.WithoutCancel(ctx), previous.Metadata, previous.Document)
			}
			return err
		}
		return nil
	})
}

func (a App) authList(ctx context.Context, name string, stdout, stderr io.Writer) int {
	cfg, err := config.LoadOrDefault(a.paths.ConfigFile)
	if err != nil {
		return exitError(stderr, authCLIError(errors.New("configuration unavailable")))
	}
	names := make([]string, 0, len(cfg.AuthProfiles))
	for candidate := range cfg.AuthProfiles {
		if name == "" || name == candidate {
			names = append(names, candidate)
		}
	}
	sort.Strings(names)
	if name != "" && len(names) == 0 {
		return exitError(stderr, authCLIError(errors.New("authentication profile not found")))
	}
	rows := make([][]string, 0, len(names))
	headers := []string{"NAME", "PROVIDER", "ACCOUNT", "DELIVERY"}
	if name != "" {
		headers = append(headers, "STATE", "EXPIRES")
	}
	for _, candidate := range names {
		metadata, err := a.authStore().ReadMetadata(cfg.AuthProfiles[candidate])
		if err != nil || metadata.Name != candidate {
			return exitError(stderr, authCLIError(errors.New("authentication metadata unavailable")))
		}
		row := []string{candidate, metadata.Provider, metadata.Account, "host-only"}
		if name != "" {
			record, err := a.authStore().Read(ctx, cfg.AuthProfiles[candidate])
			if err != nil {
				return exitError(stderr, authCLIError(err))
			}
			expiry, err := authstate.Expiry(record.Document, record.Metadata.ExpiresField)
			record.Zero()
			if err != nil {
				return exitError(stderr, authCLIError(err))
			}
			state, expires := "stored (expiry unknown)", ""
			if !expiry.IsZero() {
				expires = expiry.UTC().Format(time.RFC3339)
				now := time.Now()
				if a.now != nil {
					now = a.now()
				}
				state = "ready"
				if !expiry.After(now.Add(30 * time.Second)) {
					state = "host sign-in required"
					if metadata.Provider == "github" && metadata.RefreshField != "" && metadata.ClientID != "" {
						state = "host refresh on next use"
					}
				}
			}
			row = append(row, state, expires)
		}
		rows = append(rows, row)
	}
	if err := writeTable(stdout, headers, rows); err != nil {
		return exitError(stderr, err)
	}
	return 0
}

func (a App) loginGitHubCLI(ctx context.Context, scopes []string, messages io.Writer) ([]byte, error) {
	gh, err := exec.LookPath("gh")
	if err != nil {
		return nil, errors.New("install gh on the host or supply --client-id")
	}
	if err := os.MkdirAll(a.paths.DataDir, 0700); err != nil {
		return nil, errors.New("private host login directory unavailable")
	}
	dir, err := os.MkdirTemp(a.paths.DataDir, ".github-login-")
	if err != nil {
		return nil, errors.New("private host login directory unavailable")
	}
	defer os.RemoveAll(dir)
	// A temporary HOME does not isolate Git's system configuration. Apple Git
	// supplies osxkeychain there, and gh's Git setup can approve the new token
	// through that helper even with --insecure-storage. Keep all Git state in
	// this directory and select gh itself, so the separate Git setup flow is
	// unnecessary and cannot send the token to a host credential helper.
	gitConfig := filepath.Join(dir, "gitconfig")
	if err := os.WriteFile(gitConfig, []byte("[credential \"https://github.com\"]\n\thelper =\n\thelper = !gh auth git-credential\n"), 0600); err != nil {
		return nil, errors.New("private host Git configuration unavailable")
	}
	environment := []string{
		"HOME=" + dir, "GH_CONFIG_DIR=" + filepath.Join(dir, "gh"),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=" + os.DevNull, "GIT_CONFIG_GLOBAL=" + gitConfig,
		"GH_NO_UPDATE_NOTIFIER=1", "DO_NOT_TRACK=1", "GH_TELEMETRY=0",
	}
	for _, key := range []string{"PATH", "TERM", "SystemRoot", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if value := os.Getenv(key); value != "" {
			environment = append(environment, key+"="+value)
		}
	}
	args := []string{"auth", "login", "--hostname", "github.com", "--git-protocol", "https", "--web", "--insecure-storage", "--skip-ssh-key"}
	if len(scopes) > 0 {
		args = append(args, "--scopes", strings.Join(scopes, ","))
	}
	login := exec.CommandContext(ctx, gh, args...)
	login.Env, login.Dir, login.Stdin, login.Stdout, login.Stderr = environment, dir, a.commandStdin(), messages, messages
	if login.Run() != nil {
		return nil, errors.New("host GitHub login failed or was cancelled")
	}
	var output bytes.Buffer
	read := exec.CommandContext(ctx, gh, "auth", "token", "--hostname", "github.com")
	read.Env, read.Dir, read.Stdout, read.Stderr = environment, dir, &output, io.Discard
	if read.Run() != nil {
		return nil, errors.New("host GitHub token retrieval failed")
	}
	defer keyring.Zero(output.Bytes())
	document, err := json.Marshal(map[string]string{"access_token": strings.TrimSpace(output.String())})
	if err != nil {
		return nil, errors.New("host GitHub state encoding failed")
	}
	return document, nil
}
