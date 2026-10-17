package cli

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/trknhr/envvault/internal/admin"
	"github.com/trknhr/envvault/internal/audit"
	"github.com/trknhr/envvault/internal/bootstrap"
	"github.com/trknhr/envvault/internal/browser"
	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/config"
	doctorpkg "github.com/trknhr/envvault/internal/doctor"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/homefile"
	"github.com/trknhr/envvault/internal/issuer"
	"github.com/trknhr/envvault/internal/issuer/local"
	"github.com/trknhr/envvault/internal/jwks"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/process"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/profilemgr"
	"github.com/trknhr/envvault/internal/projectbinding"
	"github.com/trknhr/envvault/internal/providerproxy"
	resetpkg "github.com/trknhr/envvault/internal/reset"
	"github.com/trknhr/envvault/internal/sandbox"
	sandboxdocker "github.com/trknhr/envvault/internal/sandbox/docker"
	"github.com/trknhr/envvault/internal/sandboxsession"
	sessionagentinfra "github.com/trknhr/envvault/internal/sandboxsession/agentinfra"
	tokenout "github.com/trknhr/envvault/internal/token"
)

const (
	defaultJWKSFilename    = "envvault-jwks.json"
	defaultAuditFilename   = "audit.jsonl"
	resourceCleanupTimeout = 5 * time.Second
)

type ChildRunner interface {
	Run(ctx context.Context, input process.RunInput) (int, error)
}

type BrowserClient interface {
	Open(ctx context.Context, request browser.OpenRequest) (browser.OpenResult, error)
}

type ProfileManager interface {
	AddProcess(ctx context.Context, request profilemgr.ProcessRequest) (profile.Profile, error)
	AddBrowserSession(ctx context.Context, request profilemgr.BrowserSessionRequest) (profile.Profile, error)
}

type ProjectBindingConfirmation struct {
	Mode     profile.ProjectBindingMode
	Identity projectbinding.Identity
}

type ProjectBindingConfirmer interface {
	ConfirmProjectBinding(ctx context.Context, request ProjectBindingConfirmation) error
}

type Initializer interface {
	Init(ctx context.Context) (bootstrap.Result, error)
}

type Resetter interface {
	Reset(ctx context.Context, options resetpkg.Options) (resetpkg.Result, error)
}

type AdminServer interface {
	Serve(ctx context.Context, request admin.ServeRequest) error
}

type AdminController interface {
	Start(ctx context.Context, request admin.StartRequest) (admin.State, error)
	Status(ctx context.Context) (admin.Status, error)
	Stop(ctx context.Context) (admin.State, error)
}

type Doctor interface {
	Check(ctx context.Context) (doctorpkg.Result, error)
}

type DoctorRepairer interface {
	Repair(ctx context.Context) (doctorpkg.Result, error)
}

type ConfigSaver func(path string, cfg config.File) error

type Options struct {
	Paths                   config.Paths
	AgentSkillHomeDir       string
	Initializer             Initializer
	Resetter                Resetter
	Doctor                  Doctor
	Secrets                 keyring.Store
	Stdin                   io.Reader
	CredentialReader        CredentialReader
	ConfigSaver             ConfigSaver
	ParentEnv               []string
	ProjectStartDir         string
	Profiles                process.ProfileResolver
	Issuer                  issuer.Issuer
	Runner                  ChildRunner
	Browser                 BrowserClient
	ProfileManager          ProfileManager
	ProjectBindingConfirmer ProjectBindingConfirmer
	AdminServer             AdminServer
	AdminController         AdminController
	AdminTokenSource        func() (string, error)
	StdoutIsTerminal        func() bool
	Now                     func() time.Time
	SandboxRuntimes         map[string]sandbox.Runtime
	SandboxSessionRuntimes  map[string]sandboxsession.Runtime
}

type App struct {
	paths                   config.Paths
	agentSkillHomeDir       string
	initializer             Initializer
	resetter                Resetter
	doctor                  Doctor
	secrets                 keyring.Store
	stdin                   io.Reader
	credentialReader        CredentialReader
	configSaver             ConfigSaver
	parentEnv               []string
	projectStartDir         string
	profiles                process.ProfileResolver
	issuer                  issuer.Issuer
	runner                  ChildRunner
	browser                 BrowserClient
	profileManager          ProfileManager
	projectBindingConfirmer ProjectBindingConfirmer
	adminServer             AdminServer
	adminController         AdminController
	adminTokenSource        func() (string, error)
	stdoutIsTerminal        func() bool
	now                     func() time.Time
	sandboxRuntimes         map[string]sandbox.Runtime
	sandboxSessionRuntimes  map[string]sandboxsession.Runtime
}

func New(options Options) App {
	return App{
		paths:                   options.Paths,
		agentSkillHomeDir:       options.AgentSkillHomeDir,
		initializer:             options.Initializer,
		resetter:                options.Resetter,
		doctor:                  options.Doctor,
		secrets:                 options.Secrets,
		stdin:                   options.Stdin,
		credentialReader:        options.CredentialReader,
		configSaver:             options.ConfigSaver,
		parentEnv:               append([]string(nil), options.ParentEnv...),
		projectStartDir:         options.ProjectStartDir,
		profiles:                options.Profiles,
		issuer:                  options.Issuer,
		runner:                  options.Runner,
		browser:                 options.Browser,
		profileManager:          options.ProfileManager,
		projectBindingConfirmer: options.ProjectBindingConfirmer,
		adminServer:             options.AdminServer,
		adminController:         options.AdminController,
		adminTokenSource:        options.AdminTokenSource,
		stdoutIsTerminal:        options.StdoutIsTerminal,
		now:                     options.Now,
		sandboxRuntimes:         cloneSandboxRuntimes(options.SandboxRuntimes),
		sandboxSessionRuntimes:  cloneSandboxSessionRuntimes(options.SandboxSessionRuntimes),
	}
}

func defaultOptions(paths config.Paths) Options {
	agentSkillHomeDir, _ := os.UserHomeDir()
	secrets := keyring.NewOSStore()
	profiles := config.ProfileStore{Path: paths.ConfigFile}
	managedTalos := newManagedTalos(paths, secrets)
	auditRecorder := &audit.FileRecorder{Path: filepath.Join(paths.DataDir, defaultAuditFilename)}
	tokenIssuer := local.NewIssuerWithAudit(profiles, secrets, managedTalos, auditRecorder)
	return Options{
		Paths:             paths,
		AgentSkillHomeDir: agentSkillHomeDir,
		Initializer:       managedTalos,
		Secrets:           secrets,
		CredentialReader:  terminalCredentialReader(os.Stdin),
		Profiles:          profiles,
		Issuer:            tokenIssuer,
		Runner:            process.Runner{},
		Browser:           browser.Client{Issuer: tokenIssuer, Opener: browser.CommandOpener{}, Audit: auditRecorder},
		ProfileManager:    profilemgr.New(paths.ConfigFile, secrets, managedTalos),
		ProjectBindingConfirmer: ttyProjectBindingConfirmer{
			input:      os.Stdin,
			output:     os.Stderr,
			isTerminal: stdinIsTerminal,
		},
		AdminServer:      admin.Service{ConfigPath: paths.ConfigFile, Secrets: secrets},
		AdminController:  admin.Control{Paths: paths},
		AdminTokenSource: admin.NewToken,
		Resetter:         resetpkg.Planner{Paths: paths, Secrets: secrets},
		Doctor:           doctorpkg.Checker{Paths: paths, Secrets: secrets},
		SandboxRuntimes: map[string]sandbox.Runtime{
			"docker": sandboxdocker.New(sandboxdocker.Options{}),
		},
		SandboxSessionRuntimes: map[string]sandboxsession.Runtime{
			"agent-infra": sessionagentinfra.Runtime{},
		},
	}
}

func cloneSandboxRuntimes(in map[string]sandbox.Runtime) map[string]sandbox.Runtime {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]sandbox.Runtime, len(in))
	for name, runtime := range in {
		out[name] = runtime
	}
	return out
}

func Run(args []string, stdout, stderr io.Writer) int {
	paths, err := config.DefaultPaths()
	if err != nil {
		return exitError(stderr, err)
	}
	options := defaultOptions(paths)
	options.Stdin = os.Stdin
	options.StdoutIsTerminal = func() bool {
		return outputIsTerminal(stdout)
	}
	return New(options).Run(context.Background(), args, stdout, stderr)
}

func (a App) Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return a.execute(ctx, args, stdout, stderr)
}

func (a App) runInit(ctx context.Context, stderr io.Writer) int {
	if a.initializer == nil {
		return exitUnimplemented(stderr, "init")
	}
	if _, err := a.initializer.Init(ctx); err != nil {
		return exitError(stderr, err)
	}
	return 0
}

func (a App) runReset(ctx context.Context, options resetpkg.Options, confirmed bool, stdout, stderr io.Writer) int {
	if a.resetter == nil {
		return exitUnimplemented(stderr, "reset")
	}
	if !options.DryRun && !confirmed {
		fmt.Fprintln(stderr, "envvault: reset requires --yes or use --dry-run")
		return 2
	}
	result, err := a.resetter.Reset(ctx, options)
	if err != nil {
		return exitError(stderr, err)
	}
	if options.DryRun {
		writeResetPlan(stdout, result)
	}
	return 0
}

func (a App) runDoctor(ctx context.Context, repair bool, stdout, stderr io.Writer) int {
	if a.doctor == nil {
		return exitUnimplemented(stderr, "doctor")
	}
	var result doctorpkg.Result
	var err error
	if repair {
		repairer, ok := a.doctor.(DoctorRepairer)
		if !ok {
			return exitError(stderr, clerr.New(clerr.ConfigInvalid, "doctor repair is unavailable"))
		}
		result, err = repairer.Repair(ctx)
	} else {
		result, err = a.doctor.Check(ctx)
	}
	if err != nil {
		return exitError(stderr, err)
	}
	writeDoctorResult(stdout, result)
	if result.HasErrors() {
		return 1
	}
	return 0
}

func (a App) runProfileAddProcess(ctx context.Context, request profilemgr.ProcessRequest, stderr io.Writer) int {
	return a.addApprovedProfile(ctx, request.ProjectBinding.Mode, stderr, func(binding profile.ProjectBinding) error {
		request.ProjectBinding = binding
		_, err := a.profileManager.AddProcess(ctx, request)
		return err
	})
}

func (a App) runProfileAddBrowserSession(ctx context.Context, request profilemgr.BrowserSessionRequest, stderr io.Writer) int {
	return a.addApprovedProfile(ctx, request.ProjectBinding.Mode, stderr, func(binding profile.ProjectBinding) error {
		request.ProjectBinding = binding
		_, err := a.profileManager.AddBrowserSession(ctx, request)
		return err
	})
}

func (a App) addApprovedProfile(ctx context.Context, mode profile.ProjectBindingMode, stderr io.Writer, add func(profile.ProjectBinding) error) int {
	if a.profileManager == nil {
		return exitUnimplemented(stderr, "profile")
	}
	binding, err := a.approveProjectBinding(ctx, mode)
	if err != nil {
		return exitError(stderr, err)
	}
	if err := add(binding); err != nil {
		return exitError(stderr, err)
	}
	return 0
}

func (a App) runSecretAdd(ctx context.Context, name string, stderr io.Writer) int {
	if err := a.requireSecrets(); err != nil {
		return exitError(stderr, err)
	}
	raw, err := io.ReadAll(a.commandStdin())
	if err != nil {
		return exitError(stderr, clerr.Wrap(clerr.ConfigInvalid, "read api key from stdin", err))
	}
	apiKey := strings.TrimSpace(string(raw))
	if apiKey == "" {
		return exitError(stderr, clerr.New(clerr.ConfigInvalid, "api key is required"))
	}
	secret := []byte(apiKey)
	defer keyring.Zero(secret)
	return a.storeCredential(ctx, name, secret, stderr)
}

func (a App) runCredentialSetFromStdin(ctx context.Context, name string, stderr io.Writer) int {
	if err := a.requireSecrets(); err != nil {
		return exitError(stderr, err)
	}
	raw, err := io.ReadAll(a.commandStdin())
	if err != nil {
		return exitError(stderr, clerr.Wrap(clerr.ConfigInvalid, "read credential from stdin", err))
	}
	defer keyring.Zero(raw)
	value := bytes.TrimSpace(raw)
	if len(value) == 0 {
		return exitError(stderr, clerr.New(clerr.ConfigInvalid, "credential value is required"))
	}
	return a.storeCredential(ctx, name, value, stderr)
}

func (a App) runCredentialSetInteractive(ctx context.Context, name string, stderr io.Writer) int {
	if err := a.requireSecrets(); err != nil {
		return exitError(stderr, err)
	}
	if a.credentialReader == nil {
		return exitError(stderr, clerr.New(clerr.ConfigInvalid, "interactive credential input unavailable; use envvault credential set <name> --value-stdin"))
	}
	raw, err := a.credentialReader(stderr)
	if err != nil {
		return exitError(stderr, err)
	}
	defer keyring.Zero(raw)
	value := bytes.TrimSpace(raw)
	if len(value) == 0 {
		return exitError(stderr, clerr.New(clerr.ConfigInvalid, "credential value is required"))
	}
	return a.storeCredential(ctx, name, value, stderr)
}

func (a App) requireSecrets() error {
	if a.secrets == nil {
		return clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable")
	}
	return nil
}

func (a App) commandStdin() io.Reader {
	if a.stdin != nil {
		return a.stdin
	}
	return os.Stdin
}

func (a App) storeCredential(ctx context.Context, name string, value []byte, stderr io.Writer) int {
	if err := a.secrets.Put(ctx, keyring.CredentialValue(name), value); err != nil {
		return exitError(stderr, err)
	}
	if err := a.recordCredentialName(name); err != nil {
		_ = a.secrets.Delete(ctx, keyring.CredentialValue(name))
		return exitError(stderr, err)
	}
	return 0
}

func (a App) runCredentialDelete(ctx context.Context, name string, cascade bool, stderr io.Writer) int {
	if err := a.requireSecrets(); err != nil {
		return exitError(stderr, err)
	}
	cfg, err := config.LoadOrDefault(a.paths.ConfigFile)
	if err != nil {
		return exitError(stderr, err)
	}
	name = strings.TrimSpace(name)
	if !cfg.RemoveCredential(name) {
		return exitError(stderr, clerr.New(clerr.ConfigInvalid, "credential not found"))
	}
	referencingProfiles := profilesUsingCredential(cfg, name)
	if len(referencingProfiles) > 0 && !cascade {
		return exitError(stderr, clerr.New(clerr.ConfigInvalid, "credential is used by profiles: "+strings.Join(referencingProfiles, ", ")+"; pass --cascade to delete them too"))
	}

	value, err := a.secrets.Get(ctx, keyring.CredentialValue(name))
	if err != nil {
		return exitError(stderr, err)
	}
	defer keyring.Zero(value)
	if err := a.secrets.Delete(ctx, keyring.CredentialValue(name)); err != nil {
		return exitError(stderr, err)
	}
	for _, profileName := range referencingProfiles {
		delete(cfg.Profiles, profileName)
	}
	saveConfig := a.configSaver
	if saveConfig == nil {
		saveConfig = config.Save
	}
	if err := saveConfig(a.paths.ConfigFile, cfg); err != nil {
		if restoreErr := a.secrets.Put(context.WithoutCancel(ctx), keyring.CredentialValue(name), value); restoreErr != nil {
			fmt.Fprintln(stderr, clerr.Wrap(clerr.CleanupFailed, "restore credential after config update failed", restoreErr))
		}
		return exitError(stderr, err)
	}
	return 0
}

func profilesUsingCredential(cfg config.File, credentialName string) []string {
	names := make([]string, 0)
	for name, stored := range cfg.Profiles {
		if strings.TrimSpace(stored.CredentialName) == credentialName {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func (a App) runCredentialList(stdout, stderr io.Writer) int {
	cfg, err := config.LoadOrDefault(a.paths.ConfigFile)
	if err != nil {
		return exitError(stderr, err)
	}
	rows := make([][]string, 0, len(cfg.CredentialNames()))
	for _, name := range cfg.CredentialNames() {
		rows = append(rows, []string{name})
	}
	if err := writeTable(stdout, []string{"NAME"}, rows); err != nil {
		return exitError(stderr, err)
	}
	return 0
}

func (a App) runProfileList(stdout, stderr io.Writer) int {
	return a.writeProfileList(stdout, stderr, nil, []string{"NAME", "KIND", "CREDENTIAL", "TARGET", "BINDING"}, func(name string, stored config.Profile) []string {
		return []string{
			name,
			string(stored.Kind),
			stored.CredentialName,
			listTarget(stored),
			listProjectBinding(stored.ProjectBinding.Mode),
		}
	})
}

func (a App) runProxyList(stdout, stderr io.Writer) int {
	return a.writeProfileList(stdout, stderr, func(stored config.Profile) bool {
		return stored.Kind == profile.KindProviderProxy
	}, []string{"NAME", "CREDENTIAL", "TARGET", "BINDING"}, func(name string, stored config.Profile) []string {
		return []string{
			name,
			stored.CredentialName,
			listTarget(stored),
			listProjectBinding(stored.ProjectBinding.Mode),
		}
	})
}

func (a App) writeProfileList(stdout, stderr io.Writer, include func(config.Profile) bool, header []string, row func(string, config.Profile) []string) int {
	cfg, err := config.LoadOrDefault(a.paths.ConfigFile)
	if err != nil {
		return exitError(stderr, err)
	}
	names := make([]string, 0, len(cfg.Profiles))
	for name := range cfg.Profiles {
		names = append(names, name)
	}
	slices.Sort(names)

	rows := make([][]string, 0, len(names))
	for _, name := range names {
		stored := cfg.Profiles[name]
		if include != nil && !include(stored) {
			continue
		}
		rows = append(rows, row(name, stored))
	}
	if err := writeTable(stdout, header, rows); err != nil {
		return exitError(stderr, err)
	}
	return 0
}

func writeTable(stdout io.Writer, header []string, rows [][]string) error {
	writer := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, strings.Join(header, "\t"))
	for _, row := range rows {
		fmt.Fprintln(writer, strings.Join(row, "\t"))
	}
	return writer.Flush()
}

func listTarget(stored config.Profile) string {
	if strings.TrimSpace(stored.TargetURL) == "" {
		return "-"
	}
	return stored.TargetURL
}

func listProjectBinding(mode profile.ProjectBindingMode) string {
	if mode == "" {
		return string(profile.ProjectBindingNone)
	}
	return string(mode)
}

func (a App) runProxyAdd(ctx context.Context, request proxyAddRequest, stdout, stderr io.Writer) int {
	binding, err := a.approveProjectBinding(ctx, request.ProjectBinding.Mode)
	if err != nil {
		return exitError(stderr, err)
	}
	request.ProjectBinding = binding
	if err := a.saveNewProfile(request.Name, config.Profile{
		Kind:           profile.KindProviderProxy,
		CredentialName: request.CredentialName,
		AuthMode:       request.AuthMode,
		Provider:       request.Provider,
		TargetURL:      request.TargetURL,
		AllowedPaths:   append([]string(nil), request.AllowedPaths...),
		AllowedMethods: append([]string(nil), request.AllowedMethods...),
		LocalTokenTTL:  config.Duration(request.LocalTokenTTL),
		ProjectBinding: config.ProjectBindingFrom(request.ProjectBinding),
	}); err != nil {
		return exitError(stderr, err)
	}
	fmt.Fprintln(stdout, "Add this to your .env:")
	fmt.Fprint(stdout, envref.ProxyDotenv(request.Name))
	return 0
}

func (a App) runInjectAdd(ctx context.Context, request injectAddRequest, stderr io.Writer) int {
	binding, err := a.approveProjectBinding(ctx, request.ProjectBinding.Mode)
	if err != nil {
		return exitError(stderr, err)
	}
	request.ProjectBinding = binding
	if err := a.saveNewProfile(request.Name, config.Profile{
		Kind:           profile.KindInject,
		CredentialName: request.CredentialName,
		ProjectBinding: config.ProjectBindingFrom(request.ProjectBinding),
	}); err != nil {
		return exitError(stderr, err)
	}
	return 0
}

func (a App) saveNewProfile(name string, stored config.Profile) error {
	cfg, err := config.LoadOrDefault(a.paths.ConfigFile)
	if err != nil {
		return err
	}
	if err := cfg.AddProfile(name, stored); err != nil {
		return err
	}
	return config.Save(a.paths.ConfigFile, cfg)
}

func (a App) recordCredentialName(name string) error {
	if strings.TrimSpace(a.paths.ConfigFile) == "" {
		return nil
	}
	cfg, err := config.LoadOrDefault(a.paths.ConfigFile)
	if err != nil {
		return err
	}
	cfg.AddCredential(name)
	return config.Save(a.paths.ConfigFile, cfg)
}

func (a App) runAdminServe(ctx context.Context, request admin.ServeRequest, stdout, stderr io.Writer) int {
	if a.adminServer == nil {
		return exitUnimplemented(stderr, "admin")
	}
	if request.Token == "" && request.TokenEnv != "" {
		request.Token = strings.TrimSpace(os.Getenv(request.TokenEnv))
		if request.Token == "" {
			return exitError(stderr, clerr.New(clerr.ConfigInvalid, "admin token env is empty"))
		}
	}
	if request.Token == "" {
		tokenSource := a.adminTokenSource
		if tokenSource == nil {
			tokenSource = admin.NewToken
		}
		token, err := tokenSource()
		if err != nil {
			return exitError(stderr, err)
		}
		request.Token = token
	}
	request.Stdout = stdout
	if err := a.adminServer.Serve(ctx, request); err != nil {
		return exitError(stderr, err)
	}
	return 0
}

func (a App) runAdminStart(ctx context.Context, request admin.StartRequest, stdout, stderr io.Writer) int {
	if a.adminController == nil {
		return exitUnimplemented(stderr, "admin")
	}
	state, err := a.adminController.Start(ctx, request)
	if err != nil {
		return exitError(stderr, err)
	}
	fmt.Fprintf(stdout, "EnvVault admin: %s\n", state.URL)
	return 0
}

func (a App) runAdminStatus(ctx context.Context, stdout, stderr io.Writer) int {
	if a.adminController == nil {
		return exitUnimplemented(stderr, "admin")
	}
	status, err := a.adminController.Status(ctx)
	if err != nil {
		return exitError(stderr, err)
	}
	if !status.Running {
		fmt.Fprintln(stdout, "stopped")
		return 0
	}
	fmt.Fprintf(stdout, "running pid=%d url=%s\n", status.State.PID, status.State.URL)
	return 0
}

func (a App) runAdminStop(ctx context.Context, stdout, stderr io.Writer) int {
	if a.adminController == nil {
		return exitUnimplemented(stderr, "admin")
	}
	state, err := a.adminController.Stop(ctx)
	if err != nil {
		return exitError(stderr, err)
	}
	if state.PID == 0 {
		fmt.Fprintln(stdout, "stopped")
		return 0
	}
	fmt.Fprintf(stdout, "stopped pid=%d\n", state.PID)
	return 0
}

func (a App) approveProjectBinding(ctx context.Context, mode profile.ProjectBindingMode) (profile.ProjectBinding, error) {
	if mode == "" || mode == profile.ProjectBindingNone {
		return projectbinding.Approve(mode, projectbinding.Identity{})
	}
	identity, err := a.detectProjectIdentity(ctx)
	if err != nil {
		return profile.ProjectBinding{}, err
	}
	if err := a.confirmProjectBinding(ctx, mode, identity); err != nil {
		return profile.ProjectBinding{}, err
	}
	return projectbinding.Approve(mode, identity)
}

func (a App) confirmProjectBinding(ctx context.Context, mode profile.ProjectBindingMode, identity projectbinding.Identity) error {
	confirmer := a.projectBindingConfirmer
	if confirmer == nil {
		confirmer = autoProjectBindingConfirmer{}
	}
	return confirmer.ConfirmProjectBinding(ctx, ProjectBindingConfirmation{
		Mode:     mode,
		Identity: identity,
	})
}

func (a App) runToken(ctx context.Context, parsed tokenArgs, stdout, stderr io.Writer) int {
	if !a.tokenConfigured() {
		return exitUnimplemented(stderr, "token")
	}
	if a.tokenOutputToTerminal() && !parsed.allowTTY && !parsed.quiet {
		return exitError(stderr, clerr.New(clerr.ConfigInvalid, "token output to a terminal requires --allow-tty or --quiet"))
	}
	p, err := a.profiles.Profile(parsed.profile)
	if err != nil {
		return exitError(stderr, err)
	}
	if p.Kind != profile.KindProcess {
		return exitError(stderr, clerr.New(clerr.ProfileKindMismatch, p.Name))
	}
	projectIdentity, err := a.detectProjectIdentity(ctx)
	if err != nil {
		return exitError(stderr, err)
	}
	if err := projectbinding.Check(p.ProjectBinding, projectIdentity); err != nil {
		return exitError(stderr, err)
	}
	claims, err := process.ProcessClaims(p, projectIdentity)
	if err != nil {
		return exitError(stderr, err)
	}

	credential, err := a.issuer.Issue(ctx, issuer.Grant{
		Profile:  p.Name,
		Resource: p.Resource,
		Scopes:   append([]string(nil), p.Scopes...),
		TTL:      p.TokenTTL,
		Claims:   claims,
	})
	if err != nil {
		return exitError(stderr, err)
	}
	if a.tokenOutputToTerminal() && parsed.allowTTY && !parsed.quiet {
		fmt.Fprintln(stderr, "warning: writing a leased token to a terminal")
	}
	if err := tokenout.Write(stdout, tokenout.Output{
		Format:     parsed.format,
		Credential: credential,
		Profile:    p.Name,
		Resource:   p.Resource,
		Now:        a.nowTime(),
	}); err != nil {
		return exitError(stderr, err)
	}
	return 0
}

func (a App) tokenConfigured() bool {
	return a.profiles != nil && a.issuer != nil
}

func (a App) tokenOutputToTerminal() bool {
	return a.stdoutIsTerminal != nil && a.stdoutIsTerminal()
}

func (a App) nowTime() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

func (a App) runExec(ctx context.Context, parsed execArgs, stdout, stderr io.Writer) int {
	for _, assignment := range parsed.inlineEnv {
		if err := validateEnvAssignment(assignment); err != nil {
			return exitError(stderr, err)
		}
	}
	if !a.execConfigured() {
		return exitUnimplemented(stderr, "exec")
	}
	parentEnvironment := a.parentEnvironment()
	homeFileSourceDir := ""
	var err error
	if homefile.RequiresSourceDir(parsed.homeFiles) {
		homeFileSourceDir, err = a.homeFileSourceDir()
		if err != nil {
			return exitError(stderr, err)
		}
	}
	projectIdentity, err := a.detectProjectIdentity(ctx)
	if err != nil {
		return exitError(stderr, err)
	}
	refResolver := &providerproxy.EnvResolver{
		Profiles: a.profiles,
		Secrets:  a.secrets,
	}
	defer closeQuietly(refResolver.Close)
	env, err := process.BuildEnv(ctx, process.EnvInput{
		Parent:            parentEnvironment,
		EnvFiles:          parsed.envFiles,
		InlineEnv:         parsed.inlineEnv,
		ProjectIdentity:   projectIdentity,
		ReferenceResolver: refResolver,
	}, a.profiles, a.issuer)
	if err != nil {
		return exitError(stderr, err)
	}
	var homeWorkspace *homefile.Workspace
	if len(parsed.homeFiles) > 0 {
		homeWorkspace, err = homefile.Prepare(ctx, homefile.Options{
			CacheDir:  a.paths.CacheDir,
			SourceDir: homeFileSourceDir,
			Specs:     parsed.homeFiles,
			Secrets:   a.secrets,
		})
		if err != nil {
			return exitError(stderr, err)
		}
		homeWorkspace.ApplyEnvironment(env)
		defer homeWorkspace.Close()
	}
	signals := make(chan os.Signal, 1)
	process.NotifyInterrupt(signals)
	defer signal.Stop(signals)

	code, err := a.runner.Run(ctx, process.RunInput{
		Command: parsed.command,
		Env:     env,
		Signals: signals,
		Stdout:  stdout,
		Stderr:  stderr,
	})
	var cleanupErr error
	if homeWorkspace != nil {
		cleanupErr = homeWorkspace.Close()
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		if cleanupErr != nil {
			fmt.Fprintln(stderr, cleanupErr)
		}
		return 1
	}
	if cleanupErr != nil {
		fmt.Fprintln(stderr, cleanupErr)
		if code == 0 {
			return 1
		}
	}
	return code
}

func (a App) homeFileSourceDir() (string, error) {
	return a.absoluteInvocationDir("get current directory for --home-file", "resolve current directory for --home-file")
}

func (a App) detectProjectIdentity(ctx context.Context) (projectbinding.Identity, error) {
	start, err := a.invocationDir("get current directory")
	if err != nil {
		return projectbinding.Identity{}, err
	}
	return projectbinding.Detect(ctx, start)
}

func (a App) invocationDir(missingDetail string) (string, error) {
	if a.projectStartDir != "" {
		return a.projectStartDir, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", clerr.Wrap(clerr.ConfigInvalid, missingDetail, err)
	}
	return cwd, nil
}

func (a App) absoluteInvocationDir(getDetail, resolveDetail string) (string, error) {
	start, err := a.invocationDir(getDetail)
	if err != nil {
		return "", err
	}
	absolute, err := filepath.Abs(start)
	if err != nil {
		return "", clerr.Wrap(clerr.ConfigInvalid, resolveDetail, err)
	}
	return filepath.Clean(absolute), nil
}

func closeQuietly(close func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), resourceCleanupTimeout)
	defer cancel()
	_ = close(ctx)
}

func (a App) runOpen(ctx context.Context, parsed openArgs, stdout, stderr io.Writer) int {
	if !a.openConfigured() {
		return exitUnimplemented(stderr, "open")
	}
	p, err := a.profiles.Profile(parsed.profile)
	if err != nil {
		return exitError(stderr, err)
	}
	if p.Kind != profile.KindBrowserSession {
		return exitError(stderr, clerr.New(clerr.ProfileKindMismatch, p.Name))
	}
	projectIdentity, err := a.detectProjectIdentity(ctx)
	if err != nil {
		return exitError(stderr, err)
	}
	if err := projectbinding.Check(p.ProjectBinding, projectIdentity); err != nil {
		return exitError(stderr, err)
	}

	result, err := a.browser.Open(ctx, browser.OpenRequest{
		Profile:         p,
		Browser:         parsed.browser,
		PrintURL:        parsed.printURL,
		ProjectIdentity: projectIdentity,
	})
	if err != nil {
		return exitError(stderr, err)
	}
	if parsed.printURL {
		fmt.Fprintln(stdout, result.LaunchURL)
	}
	return 0
}

func (a App) openConfigured() bool {
	return a.profiles != nil && a.browser != nil
}

func (a App) execConfigured() bool {
	return a.runner != nil
}

func (a App) parentEnvironment() []string {
	if a.parentEnv == nil {
		return os.Environ()
	}
	return append([]string(nil), a.parentEnv...)
}

type autoProjectBindingConfirmer struct{}

func (autoProjectBindingConfirmer) ConfirmProjectBinding(context.Context, ProjectBindingConfirmation) error {
	return nil
}

type ttyProjectBindingConfirmer struct {
	input      io.Reader
	output     io.Writer
	isTerminal func() bool
}

func (c ttyProjectBindingConfirmer) ConfirmProjectBinding(ctx context.Context, request ProjectBindingConfirmation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.isTerminal == nil || !c.isTerminal() {
		return clerr.New(clerr.ProjectNotTrusted, "project binding approval requires an interactive terminal")
	}
	input := c.input
	if input == nil {
		input = os.Stdin
	}
	output := c.output
	if output == nil {
		output = io.Discard
	}
	writeProjectBindingPrompt(output, request)
	scanner := bufio.NewScanner(input)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return clerr.Wrap(clerr.ProjectNotTrusted, "read project binding approval", err)
		}
		return clerr.New(clerr.ProjectNotTrusted, "project binding approval required")
	}
	if strings.ToLower(strings.TrimSpace(scanner.Text())) != "yes" {
		return clerr.New(clerr.ProjectNotTrusted, "project binding approval denied")
	}
	return nil
}

func writeProjectBindingPrompt(output io.Writer, request ProjectBindingConfirmation) {
	fmt.Fprintln(output, "envvault: trust this project for the profile binding?")
	fmt.Fprintf(output, "mode: %s\n", request.Mode)
	if request.Identity.Root != "" {
		fmt.Fprintf(output, "project root: %s\n", request.Identity.Root)
	}
	if request.Identity.GitRemote != "" {
		fmt.Fprintf(output, "git remote: %s\n", request.Identity.GitRemote)
	}
	fmt.Fprint(output, "Type yes to approve: ")
}

func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func outputIsTerminal(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func (a App) runJWKSShow(stdout, stderr io.Writer) int {
	body, err := os.ReadFile(a.jwksPath())
	if err != nil {
		return exitError(stderr, clerr.Wrap(clerr.ConfigInvalid, "read jwks file", err))
	}
	if _, err := stdout.Write(body); err != nil {
		return exitError(stderr, clerr.Wrap(clerr.ConfigInvalid, "write jwks", err))
	}
	if len(body) == 0 || body[len(body)-1] != '\n' {
		if _, err := fmt.Fprintln(stdout); err != nil {
			return exitError(stderr, clerr.Wrap(clerr.ConfigInvalid, "write jwks newline", err))
		}
	}
	return 0
}

func (a App) runJWKSExport(output string, stderr io.Writer) int {
	body, err := os.ReadFile(a.jwksPath())
	if err != nil {
		return exitError(stderr, clerr.Wrap(clerr.ConfigInvalid, "read jwks file", err))
	}
	if err := jwks.Export(output, body); err != nil {
		return exitError(stderr, err)
	}
	return 0
}

func (a App) runIssuerShow(stdout, stderr io.Writer) int {
	cfg, err := config.Load(a.paths.ConfigFile)
	if err != nil {
		return exitError(stderr, err)
	}
	fmt.Fprintf(stdout, "envvault-local:%s\n", cfg.Installation.ID)
	return 0
}

func (a App) jwksPath() string {
	return filepath.Join(a.paths.DataDir, defaultJWKSFilename)
}

func writeResetPlan(writer io.Writer, result resetpkg.Result) {
	for _, path := range result.Files {
		fmt.Fprintf(writer, "file %s\n", path)
	}
	for _, key := range result.KeyringKeys {
		fmt.Fprintf(writer, "keyring %s\n", key)
	}
}

func writeDoctorResult(writer io.Writer, result doctorpkg.Result) {
	for _, check := range result.Checks {
		if check.Code != "" {
			fmt.Fprintf(writer, "%s %s: %s (%s)\n", check.Status, check.Name, check.Message, check.Code)
			continue
		}
		fmt.Fprintf(writer, "%s %s: %s\n", check.Status, check.Name, check.Message)
	}
}

type proxyAddRequest struct {
	Name           string
	CredentialName string
	AuthMode       string
	Provider       string
	TargetURL      string
	AllowedPaths   []string
	AllowedMethods []string
	LocalTokenTTL  time.Duration
	ProjectBinding profile.ProjectBinding
}

type injectAddRequest struct {
	Name           string
	CredentialName string
	ProjectBinding profile.ProjectBinding
}

func defaultOpenAICompatiblePaths() []string {
	return []string{
		"/chat/completions",
		"/responses",
		"/embeddings",
	}
}

func uniqueStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !slices.Contains(out, value) {
			out = append(out, value)
		}
	}
	return out
}

func hostFromURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return "", clerr.New(clerr.ConfigInvalid, "resource url is invalid")
	}
	return parsed.Hostname(), nil
}

type tokenArgs struct {
	profile  string
	format   tokenout.Format
	allowTTY bool
	quiet    bool
}

func parseTokenFormat(raw string) (tokenout.Format, error) {
	switch tokenout.Format(raw) {
	case tokenout.FormatRaw, tokenout.FormatJSON:
		return tokenout.Format(raw), nil
	default:
		return "", clerr.New(clerr.ConfigInvalid, "unknown token output format")
	}
}

type execArgs struct {
	envFiles  []string
	inlineEnv []string
	homeFiles []homefile.Spec
	command   []string
}

type openArgs struct {
	profile  string
	browser  string
	printURL bool
}

func validateEnvAssignment(raw string) error {
	key, value, ok := strings.Cut(raw, "=")
	if !ok || key == "" {
		return clerr.New(clerr.ConfigInvalid, "--env requires KEY=VALUE")
	}
	_, _, err := envref.ParseValue(value)
	return err
}
