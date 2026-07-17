package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trknhr/envvault/internal/admin"
	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/homefile"
	resetpkg "github.com/trknhr/envvault/internal/reset"
	tokenout "github.com/trknhr/envvault/internal/token"
)

type commandExecution struct {
	exitCode int
}

const completionUsage = "envvault: usage: envvault completion <bash|zsh|fish|powershell>"

func (a App) execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	execution := &commandExecution{}
	root := a.newRootCommand(execution)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)

	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(stderr, "envvault: %v\n", err)
		return 2
	}
	return execution.exitCode
}

func (a App) newRootCommand(execution *commandExecution) *cobra.Command {
	root := &cobra.Command{
		Use:   "envvault",
		Short: "Resolve credentials when launching a process",
		Long:  "EnvVault keeps real credentials in the OS credential store and resolves envvault:// references at process launch.",
		Example: commandExamples(
			"envvault admin start",
			"envvault credential set <name>",
			"envvault credential set <name> --value-stdin",
			"envvault credential delete <name>",
			"envvault credential list",
			"envvault exec --env KEY=envvault://<credential> -- <command>",
			"envvault proxy list",
			"envvault version",
		),
		Version:       strings.TrimSpace(versionOutput()),
		SilenceErrors: true,
		SilenceUsage:  true,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.ErrOrStderr(), "envvault: command required")
			execution.exitCode = 2
		},
	}
	root.SetVersionTemplate("{{.Version}}\n")
	root.CompletionOptions.DisableDefaultCmd = true

	root.AddCommand(
		a.newInitCommand(execution),
		a.newResetCommand(execution),
		a.newDoctorCommand(execution),
		a.newProfileCommand(execution),
		a.newCredentialCommand(execution),
		a.newSecretCommand(execution),
		a.newProxyCommand(execution),
		a.newInjectCommand(execution),
		a.newAdminCommand(execution),
		a.newTokenCommand(execution),
		a.newExecCommand(execution),
		a.newOpenCommand(execution),
		a.newJWKSCommand(execution),
		a.newIssuerCommand(execution),
		newCompletionCommand(execution),
		newVersionCommand(execution),
	)
	return root
}

func (a App) newInitCommand(execution *commandExecution) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize local EnvVault state",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			execution.exitCode = a.runInit(cmd.Context(), cmd.ErrOrStderr())
		},
	}
}

func (a App) newResetCommand(execution *commandExecution) *cobra.Command {
	var dryRun bool
	var confirmed bool
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Remove EnvVault-owned local state",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			execution.exitCode = a.runReset(cmd.Context(), resetpkg.Options{DryRun: dryRun}, confirmed, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print the state that would be removed")
	cmd.Flags().BoolVar(&confirmed, "yes", false, "Confirm removal")
	return cmd
}

func (a App) newDoctorCommand(execution *commandExecution) *cobra.Command {
	var repair bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Inspect local EnvVault state",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			execution.exitCode = a.runDoctor(cmd.Context(), repair, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().BoolVar(&repair, "repair", false, "Repair safe local-state problems")
	return cmd
}

func (a App) newAdminCommand(execution *commandExecution) *cobra.Command {
	adminCommand := newCommandGroup(
		"admin",
		"Run the local admin server",
		"envvault: usage: envvault admin <start|status|stop|serve>",
		execution,
	)
	adminCommand.AddCommand(
		a.newAdminServeCommand(execution),
		a.newAdminStartCommand(execution),
		&cobra.Command{
			Use:   "status",
			Short: "Show local admin server status",
			Args:  cobra.NoArgs,
			Run: func(cmd *cobra.Command, _ []string) {
				execution.exitCode = a.runAdminStatus(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr())
			},
		},
		&cobra.Command{
			Use:   "stop",
			Short: "Stop the local admin server",
			Args:  cobra.NoArgs,
			Run: func(cmd *cobra.Command, _ []string) {
				execution.exitCode = a.runAdminStop(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr())
			},
		},
	)
	return adminCommand
}

func (a App) newAdminServeCommand(execution *commandExecution) *cobra.Command {
	request := admin.ServeRequest{Addr: admin.DefaultAddr}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the local admin UI in the foreground",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			if strings.TrimSpace(request.Addr) == "" {
				failCommand(execution, cmd, clerr.New(clerr.ConfigInvalid, "--addr requires an address"))
				return
			}
			request.Token = strings.TrimSpace(request.Token)
			execution.exitCode = a.runAdminServe(cmd.Context(), request, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&request.Addr, "addr", request.Addr, "Listen address")
	cmd.Flags().StringVar(&request.Token, "token", "", "Admin bearer token")
	cmd.Flags().StringVar(&request.TokenEnv, "token-env", "", "Environment variable containing the admin token")
	return cmd
}

func (a App) newAdminStartCommand(execution *commandExecution) *cobra.Command {
	request := admin.StartRequest{Addr: admin.DefaultAddr}
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the local admin server",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			if strings.TrimSpace(request.Addr) == "" {
				failCommand(execution, cmd, clerr.New(clerr.ConfigInvalid, "--addr requires an address"))
				return
			}
			execution.exitCode = a.runAdminStart(cmd.Context(), request, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&request.Addr, "addr", request.Addr, "Listen address")
	return cmd
}

func (a App) newTokenCommand(execution *commandExecution) *cobra.Command {
	format := string(tokenout.FormatRaw)
	var allowTTY bool
	var quiet bool
	cmd := &cobra.Command{
		Use:   "token <profile>",
		Short: "Issue a process token",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			parsedFormat, err := parseTokenFormat(format)
			if err != nil {
				failCommand(execution, cmd, err)
				return
			}
			execution.exitCode = a.runToken(cmd.Context(), tokenArgs{
				profile:  args[0],
				format:   parsedFormat,
				allowTTY: allowTTY,
				quiet:    quiet,
			}, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&format, "format", format, "Output format: raw or json")
	cmd.Flags().BoolVar(&allowTTY, "allow-tty", false, "Allow raw token output to a terminal")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "Suppress terminal token warnings")
	return cmd
}

func (a App) newExecCommand(execution *commandExecution) *cobra.Command {
	var envFiles []string
	var inlineEnv []string
	var homeFiles []string
	cmd := &cobra.Command{
		Use:   "exec [flags] -- <command>",
		Short: "Run a child process with resolved credentials",
		Long: strings.TrimSpace(`Run a child process after resolving EnvVault references.

Options accept repeatable --env-file <path>, --env KEY=VALUE, and
--home-file DEST=SOURCE values. Relative sources are read from the current
directory, and absolute sources are accepted. The .json, .yaml, .yml, or .toml
suffix selects the template format; extensionless sources default to JSON.
Templates resolve whole-string direct envvault:// credential references. A bare
PATH uses PATH as both destination and source. DEST=envvault://CREDENTIAL writes
one raw credential instead. Destinations live in a private isolated HOME until
the child exits.`),
		Example: commandExamples(
			"envvault exec --env-file .env -- <command>",
			"envvault exec --env OPENAI_API_KEY=envvault://openai/dev -- npm run dev",
			"envvault exec --home-file .hogehoge=./config/hogehoge.yaml -- your-command",
			"envvault exec --home-file .hogehoge -- your-command",
			"envvault exec --home-file .token=envvault://hogehoge/auth -- your-command",
			"envvault exec --env OPENAI_BASE_URL=envvault://openai-proxy/dev/base-url --env OPENAI_API_KEY=envvault://openai-proxy/dev/token -- npm run dev",
		),
		Args: validateExecCommand,
		Run: func(cmd *cobra.Command, args []string) {
			parsedHomeFiles, err := homefile.ParseAll(homeFiles)
			if err != nil {
				failCommand(execution, cmd, err)
				return
			}
			execution.exitCode = a.runExec(cmd.Context(), execArgs{
				envFiles:  append([]string(nil), envFiles...),
				inlineEnv: append([]string(nil), inlineEnv...),
				homeFiles: parsedHomeFiles,
				command:   append([]string(nil), args...),
			}, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringArrayVar(&envFiles, "env-file", nil, "Read KEY=VALUE entries from a dotenv file (repeatable)")
	cmd.Flags().StringArrayVar(&inlineEnv, "env", nil, "Add KEY=VALUE to the child environment (repeatable)")
	cmd.Flags().StringArrayVar(&homeFiles, "home-file", nil, "Resolve DEST=SOURCE JSON/YAML/TOML into an isolated HOME (repeatable)")
	return cmd
}

func validateExecCommand(cmd *cobra.Command, args []string) error {
	dash := cmd.ArgsLenAtDash()
	if dash < 0 {
		return clerr.New(clerr.ConfigInvalid, "exec requires -- child command")
	}
	if dash != 0 {
		return clerr.New(clerr.ConfigInvalid, "exec arguments must be followed by -- child command")
	}
	if len(args) == 0 {
		return clerr.New(clerr.ConfigInvalid, "child command is required")
	}
	return nil
}

func (a App) newOpenCommand(execution *commandExecution) *cobra.Command {
	var browserName string
	var printURL bool
	cmd := &cobra.Command{
		Use:   "open <profile>",
		Short: "Start a browser session",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			execution.exitCode = a.runOpen(cmd.Context(), openArgs{
				profile:  args[0],
				browser:  browserName,
				printURL: printURL,
			}, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&browserName, "browser", "", "Browser name")
	cmd.Flags().BoolVar(&printURL, "print-url", false, "Print the launch URL")
	return cmd
}

func (a App) newJWKSCommand(execution *commandExecution) *cobra.Command {
	jwksCommand := newCommandGroup(
		"jwks",
		"Show or export the local JWKS",
		"envvault: jwks subcommand required",
		execution,
	)
	showCommand := &cobra.Command{
		Use:   "show",
		Short: "Show the local JWKS",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			execution.exitCode = a.runJWKSShow(cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	var output string
	exportCommand := &cobra.Command{
		Use:   "export",
		Short: "Export the local JWKS",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			if strings.TrimSpace(output) == "" {
				failCommand(execution, cmd, clerr.New(clerr.ConfigInvalid, "jwks export requires --output"))
				return
			}
			execution.exitCode = a.runJWKSExport(output, cmd.ErrOrStderr())
		},
	}
	exportCommand.Flags().StringVar(&output, "output", "", "Output path")
	jwksCommand.AddCommand(showCommand, exportCommand)
	return jwksCommand
}

func (a App) newIssuerCommand(execution *commandExecution) *cobra.Command {
	issuerCommand := newCommandGroup(
		"issuer",
		"Show the local issuer",
		"envvault: usage: envvault issuer show",
		execution,
	)
	issuerCommand.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show the local issuer ID",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			execution.exitCode = a.runIssuerShow(cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	})
	return issuerCommand
}

func newCompletionCommand(execution *commandExecution) *cobra.Command {
	return &cobra.Command{
		Use:       "completion <bash|zsh|fish|powershell>",
		Short:     "Generate shell completion",
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				fmt.Fprintln(cmd.ErrOrStderr(), completionUsage)
				execution.exitCode = 2
				return
			}
			var err error
			switch args[0] {
			case "bash":
				err = cmd.Root().GenBashCompletionV2(cmd.OutOrStdout(), true)
			case "zsh":
				err = cmd.Root().GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				err = cmd.Root().GenFishCompletion(cmd.OutOrStdout(), true)
			case "powershell":
				err = cmd.Root().GenPowerShellCompletion(cmd.OutOrStdout())
			default:
				fmt.Fprintln(cmd.ErrOrStderr(), completionUsage)
				execution.exitCode = 2
				return
			}
			if err != nil {
				failCommand(execution, cmd, err)
			}
		},
	}
}

func newVersionCommand(execution *commandExecution) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the EnvVault CLI version",
		Run: func(cmd *cobra.Command, args []string) {
			execution.exitCode = runVersion(args, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
}

func newCommandGroup(use, short, usage string, execution *commandExecution) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.ErrOrStderr(), usage)
			execution.exitCode = 2
		},
	}
}

func newListLeaf(use, short string, execution *commandExecution, list func(io.Writer, io.Writer) int) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			execution.exitCode = list(cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
}

func failCommand(execution *commandExecution, cmd *cobra.Command, err error) {
	fmt.Fprintln(cmd.ErrOrStderr(), err)
	execution.exitCode = 1
}

func commandExamples(examples ...string) string {
	return "  " + strings.Join(examples, "\n  ")
}
