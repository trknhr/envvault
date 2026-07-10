package cli

import (
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/profilemgr"
)

func (a App) newProfileCommand(execution *commandExecution) *cobra.Command {
	profileCommand := newCommandGroup(
		"profile",
		"Manage execution profiles",
		"envvault: usage: envvault profile add <kind> <name> [options]",
		execution,
	)
	profileCommand.Hidden = true

	addCommand := newCommandGroup(
		"add",
		"Add a profile",
		"envvault: usage: envvault profile add <kind> <name> [options]",
		execution,
	)
	addCommand.AddCommand(
		a.newProfileAddProcessCommand(execution),
		a.newProfileAddBrowserSessionCommand(execution),
	)
	profileCommand.AddCommand(addCommand, newListLeaf("list", "List profiles", execution, a.runProfileList))
	return profileCommand
}

type processProfileOptions struct {
	resource       string
	scopes         []string
	tokenTTL       time.Duration
	maxTokenTTL    time.Duration
	projectBinding string
}

func (a App) newProfileAddProcessCommand(execution *commandExecution) *cobra.Command {
	options := processProfileOptions{projectBinding: string(profile.ProjectBindingGitRemoteAndRoot)}
	cmd := &cobra.Command{
		Use:   "process <name>",
		Short: "Add a process profile",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			binding, err := parseProjectBinding(options.projectBinding)
			if err != nil {
				failCommand(execution, cmd, err)
				return
			}
			request := profilemgr.ProcessRequest{
				Name:           args[0],
				Resource:       options.resource,
				Scopes:         append([]string(nil), options.scopes...),
				TokenTTL:       options.tokenTTL,
				MaxTokenTTL:    options.maxTokenTTL,
				ProjectBinding: binding,
			}
			if err := validateProcessProfile(request); err != nil {
				failCommand(execution, cmd, err)
				return
			}
			execution.exitCode = a.runProfileAddProcess(cmd.Context(), request, cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&options.resource, "resource", "", "Resource URL")
	cmd.Flags().StringArrayVar(&options.scopes, "scope", nil, "Allowed scope (repeatable)")
	cmd.Flags().DurationVar(&options.tokenTTL, "ttl", 0, "Token lifetime")
	cmd.Flags().DurationVar(&options.maxTokenTTL, "max-ttl", 0, "Maximum token lifetime")
	cmd.Flags().StringVar(&options.projectBinding, "project-binding", options.projectBinding, projectBindingUsage)
	return cmd
}

type browserSessionProfileOptions struct {
	resource          string
	exchangeURL       string
	completeURL       string
	postLoginURL      string
	scopes            []string
	bootstrapTokenTTL time.Duration
	loginCodeTTL      time.Duration
	webSessionTTL     time.Duration
	allowedHosts      []string
	projectBinding    string
}

func (a App) newProfileAddBrowserSessionCommand(execution *commandExecution) *cobra.Command {
	options := browserSessionProfileOptions{projectBinding: string(profile.ProjectBindingGitRemoteAndRoot)}
	cmd := &cobra.Command{
		Use:   "browser-session <name>",
		Short: "Add a browser-session profile",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			binding, err := parseProjectBinding(options.projectBinding)
			if err != nil {
				failCommand(execution, cmd, err)
				return
			}
			request := profilemgr.BrowserSessionRequest{
				Name:              args[0],
				Resource:          options.resource,
				ExchangeURL:       options.exchangeURL,
				CompleteURL:       options.completeURL,
				PostLoginURL:      options.postLoginURL,
				Scopes:            append([]string(nil), options.scopes...),
				BootstrapTokenTTL: options.bootstrapTokenTTL,
				LoginCodeTTL:      options.loginCodeTTL,
				WebSessionTTL:     options.webSessionTTL,
				AllowedHosts:      append([]string(nil), options.allowedHosts...),
				ProjectBinding:    binding,
			}
			if err := validateBrowserSessionProfile(&request); err != nil {
				failCommand(execution, cmd, err)
				return
			}
			execution.exitCode = a.runProfileAddBrowserSession(cmd.Context(), request, cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&options.resource, "resource", "", "Resource URL")
	cmd.Flags().StringVar(&options.exchangeURL, "exchange-url", "", "Session exchange URL")
	cmd.Flags().StringVar(&options.completeURL, "complete-url", "", "Login completion URL")
	cmd.Flags().StringVar(&options.postLoginURL, "post-login-url", "", "Post-login URL")
	cmd.Flags().StringArrayVar(&options.scopes, "scope", nil, "Allowed scope (repeatable)")
	cmd.Flags().DurationVar(&options.bootstrapTokenTTL, "bootstrap-ttl", 0, "Bootstrap token lifetime")
	cmd.Flags().DurationVar(&options.loginCodeTTL, "code-ttl", 0, "Login code lifetime")
	cmd.Flags().DurationVar(&options.webSessionTTL, "session-ttl", 0, "Web session lifetime")
	cmd.Flags().StringArrayVar(&options.allowedHosts, "allowed-host", nil, "Allowed host (repeatable)")
	cmd.Flags().StringVar(&options.projectBinding, "project-binding", options.projectBinding, projectBindingUsage)
	return cmd
}

func (a App) newCredentialCommand(execution *commandExecution) *cobra.Command {
	credentialCommand := newCommandGroup(
		"credential",
		"Manage raw credentials",
		"envvault: usage: envvault credential add <name> --value-stdin",
		execution,
	)
	credentialCommand.AddCommand(
		a.newCredentialAddCommand(execution),
		newListLeaf("list", "List credential names", execution, a.runCredentialList),
	)
	return credentialCommand
}

func (a App) newCredentialAddCommand(execution *commandExecution) *cobra.Command {
	var valueStdin bool
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Store a credential in the OS credential store",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if !valueStdin {
				failCommand(execution, cmd, clerr.New(clerr.ConfigInvalid, "credential value input is required"))
				return
			}
			execution.exitCode = a.runCredentialAdd(cmd.Context(), args[0], cmd.ErrOrStderr())
		},
	}
	cmd.Flags().BoolVar(&valueStdin, "value-stdin", false, "Read the credential value from stdin")
	return cmd
}

func (a App) newSecretCommand(execution *commandExecution) *cobra.Command {
	secretCommand := newCommandGroup(
		"secret",
		"Manage provider API keys",
		"envvault: usage: envvault secret add <name> --provider openai-compatible --api-key-stdin",
		execution,
	)
	secretCommand.AddCommand(a.newSecretAddCommand(execution))
	return secretCommand
}

func (a App) newSecretAddCommand(execution *commandExecution) *cobra.Command {
	var provider string
	var apiKeyStdin bool
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Store a provider API key",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if provider != "openai-compatible" {
				failCommand(execution, cmd, clerr.New(clerr.ConfigInvalid, "provider must be openai-compatible"))
				return
			}
			if !apiKeyStdin {
				failCommand(execution, cmd, clerr.New(clerr.ConfigInvalid, "api key input is required"))
				return
			}
			execution.exitCode = a.runSecretAdd(cmd.Context(), args[0], cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&provider, "provider", "", "Credential provider")
	cmd.Flags().BoolVar(&apiKeyStdin, "api-key-stdin", false, "Read the API key from stdin")
	return cmd
}

type proxyOptions struct {
	credentialName string
	authMode       string
	provider       string
	targetURL      string
	allowedPaths   []string
	allowedMethods []string
	localTokenTTL  time.Duration
	projectBinding string
}

func (a App) newProxyCommand(execution *commandExecution) *cobra.Command {
	proxyCommand := newCommandGroup(
		"proxy",
		"Manage provider API proxies",
		"envvault: usage: envvault proxy <add|list> [options]",
		execution,
	)
	proxyCommand.AddCommand(
		a.newProxyAddCommand(execution),
		newListLeaf("list", "List provider API proxies", execution, a.runProxyList),
	)
	return proxyCommand
}

func (a App) newProxyAddCommand(execution *commandExecution) *cobra.Command {
	options := proxyOptions{
		authMode:       "bearer",
		provider:       "generic",
		localTokenTTL:  10 * time.Minute,
		projectBinding: string(profile.ProjectBindingGitRemoteAndRoot),
	}
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a provider API proxy",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			request, err := options.request(args[0])
			if err != nil {
				failCommand(execution, cmd, err)
				return
			}
			execution.exitCode = a.runProxyAdd(cmd.Context(), request, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&options.credentialName, "credential", "", "Stored credential name (defaults to profile name)")
	cmd.Flags().StringVar(&options.authMode, "auth", options.authMode, "Upstream authentication mode")
	cmd.Flags().StringVar(&options.provider, "provider", options.provider, "generic or openai-compatible")
	cmd.Flags().StringVar(&options.targetURL, "target", "", "Provider base URL")
	cmd.Flags().StringArrayVar(&options.allowedPaths, "allow-path", nil, "Allowed request path (repeatable)")
	cmd.Flags().StringArrayVar(&options.allowedMethods, "allow-method", nil, "Allowed request method (repeatable)")
	cmd.Flags().DurationVar(&options.localTokenTTL, "token-ttl", options.localTokenTTL, "Local proxy token lifetime")
	cmd.Flags().StringVar(&options.projectBinding, "project-binding", options.projectBinding, projectBindingUsage)
	return cmd
}

func (options proxyOptions) request(name string) (proxyAddRequest, error) {
	provider := options.provider
	if provider == "" {
		provider = "generic"
	}
	if provider != "generic" && provider != "openai-compatible" {
		return proxyAddRequest{}, clerr.New(clerr.ConfigInvalid, "provider must be generic or openai-compatible")
	}
	authMode := options.authMode
	if authMode == "" {
		authMode = "bearer"
	}
	if authMode != "bearer" {
		return proxyAddRequest{}, clerr.New(clerr.ConfigInvalid, "auth must be bearer")
	}
	if strings.TrimSpace(options.targetURL) == "" {
		return proxyAddRequest{}, clerr.New(clerr.ConfigInvalid, "--target is required")
	}
	binding, err := parseProjectBinding(options.projectBinding)
	if err != nil {
		return proxyAddRequest{}, err
	}
	credentialName := options.credentialName
	if strings.TrimSpace(credentialName) == "" {
		credentialName = name
	}
	allowedPaths := append([]string(nil), options.allowedPaths...)
	if len(allowedPaths) == 0 {
		allowedPaths = defaultOpenAICompatiblePaths()
	}
	allowedMethods := make([]string, 0, len(options.allowedMethods))
	for _, method := range options.allowedMethods {
		allowedMethods = append(allowedMethods, strings.ToUpper(method))
	}
	if len(allowedMethods) == 0 {
		allowedMethods = []string{http.MethodPost}
	}
	return proxyAddRequest{
		Name:           name,
		CredentialName: credentialName,
		AuthMode:       authMode,
		Provider:       provider,
		TargetURL:      options.targetURL,
		AllowedPaths:   uniqueStrings(allowedPaths),
		AllowedMethods: uniqueStrings(allowedMethods),
		LocalTokenTTL:  options.localTokenTTL,
		ProjectBinding: binding,
	}, nil
}

func (a App) newInjectCommand(execution *commandExecution) *cobra.Command {
	injectCommand := newCommandGroup(
		"inject",
		"Manage credential-injection profiles",
		"envvault: usage: envvault inject add <name> --credential <credential> [options]",
		execution,
	)
	injectCommand.Hidden = true
	injectCommand.AddCommand(a.newInjectAddCommand(execution))
	return injectCommand
}

func (a App) newInjectAddCommand(execution *commandExecution) *cobra.Command {
	var credentialName string
	projectBinding := string(profile.ProjectBindingGitRemoteAndRoot)
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a credential-injection profile",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if strings.TrimSpace(credentialName) == "" {
				failCommand(execution, cmd, clerr.New(clerr.ConfigInvalid, "--credential is required"))
				return
			}
			binding, err := parseProjectBinding(projectBinding)
			if err != nil {
				failCommand(execution, cmd, err)
				return
			}
			execution.exitCode = a.runInjectAdd(cmd.Context(), injectAddRequest{
				Name:           args[0],
				CredentialName: credentialName,
				ProjectBinding: binding,
			}, cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&credentialName, "credential", "", "Stored credential name")
	cmd.Flags().StringVar(&projectBinding, "project-binding", projectBinding, projectBindingUsage)
	return cmd
}

func (a App) newListCommand(execution *commandExecution) *cobra.Command {
	listCommand := newCommandGroup(
		"list",
		"List credentials or profiles",
		"envvault: usage: envvault list <credentials|proxies>",
		execution,
	)
	credentials := newListLeaf("credentials", "List credential names", execution, a.runCredentialList)
	credentials.Aliases = []string{"credential"}
	proxies := newListLeaf("proxies", "List provider API proxies", execution, a.runProxyList)
	proxies.Aliases = []string{"proxy"}
	profiles := newListLeaf("profiles", "List profiles", execution, a.runProfileList)
	profiles.Aliases = []string{"profile"}
	profiles.Hidden = true
	listCommand.AddCommand(credentials, proxies, profiles)
	return listCommand
}

func parseProjectBinding(raw string) (profile.ProjectBinding, error) {
	mode := profile.ProjectBindingMode(raw)
	switch mode {
	case profile.ProjectBindingNone, profile.ProjectBindingPathHash, profile.ProjectBindingGitRemoteAndRoot:
		return profile.ProjectBinding{Mode: mode}, nil
	default:
		return profile.ProjectBinding{}, clerr.New(clerr.ConfigInvalid, "unknown project binding mode")
	}
}

func validateProcessProfile(request profilemgr.ProcessRequest) error {
	if strings.TrimSpace(request.Resource) == "" {
		return clerr.New(clerr.ConfigInvalid, "--resource is required")
	}
	if len(request.Scopes) == 0 {
		return clerr.New(clerr.ConfigInvalid, "--scope is required")
	}
	if request.TokenTTL <= 0 {
		return clerr.New(clerr.ConfigInvalid, "--ttl is required")
	}
	if request.MaxTokenTTL <= 0 {
		return clerr.New(clerr.ConfigInvalid, "--max-ttl is required")
	}
	return nil
}

func validateBrowserSessionProfile(request *profilemgr.BrowserSessionRequest) error {
	if strings.TrimSpace(request.Resource) == "" {
		return clerr.New(clerr.ConfigInvalid, "--resource is required")
	}
	if len(request.Scopes) == 0 {
		return clerr.New(clerr.ConfigInvalid, "--scope is required")
	}
	if request.ExchangeURL == "" || request.CompleteURL == "" || request.PostLoginURL == "" {
		return clerr.New(clerr.ConfigInvalid, "browser-session urls are required")
	}
	if request.BootstrapTokenTTL <= 0 || request.LoginCodeTTL <= 0 || request.WebSessionTTL <= 0 {
		return clerr.New(clerr.ConfigInvalid, "browser-session ttls are required")
	}
	if len(request.AllowedHosts) == 0 {
		host, err := hostFromURL(request.Resource)
		if err != nil {
			return err
		}
		request.AllowedHosts = []string{host}
	}
	return nil
}

const projectBindingUsage = "Project binding: none, path-hash, or git-remote-and-root"
