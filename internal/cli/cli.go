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
	tokenout "github.com/trknhr/envvault/internal/token"
)

const (
	defaultJWKSFilename  = "envvault-jwks.json"
	defaultAuditFilename = "audit.jsonl"
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
}

type App struct {
	paths                   config.Paths
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
}

func New(options Options) App {
	return App{
		paths:                   options.Paths,
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
	}
}

func defaultOptions(paths config.Paths) Options {
	secrets := keyring.NewOSStore()
	profiles := config.ProfileStore{Path: paths.ConfigFile}
	managedTalos := newManagedTalos(paths, secrets)
	auditRecorder := &audit.FileRecorder{Path: filepath.Join(paths.DataDir, defaultAuditFilename)}
	tokenIssuer := local.NewIssuerWithAudit(profiles, secrets, managedTalos, auditRecorder)
	return Options{
		Paths:            paths,
		Initializer:      managedTalos,
		Secrets:          secrets,
		CredentialReader: terminalCredentialReader(os.Stdin),
		Profiles:         profiles,
		Issuer:           tokenIssuer,
		Runner:           process.Runner{},
		Browser:          browser.Client{Issuer: tokenIssuer, Opener: browser.CommandOpener{}, Audit: auditRecorder},
		ProfileManager:   profilemgr.New(paths.ConfigFile, secrets, managedTalos),
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
	}
}

func Run(args []string, stdout, stderr io.Writer) int {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
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
		fmt.Fprintln(stderr, "envvault: command \"init\" is not implemented yet")
		return 2
	}
	if _, err := a.initializer.Init(ctx); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func (a App) runReset(ctx context.Context, options resetpkg.Options, confirmed bool, stdout, stderr io.Writer) int {
	if a.resetter == nil {
		fmt.Fprintln(stderr, "envvault: command \"reset\" is not implemented yet")
		return 2
	}
	if !options.DryRun && !confirmed {
		fmt.Fprintln(stderr, "envvault: reset requires --yes or use --dry-run")
		return 2
	}
	result, err := a.resetter.Reset(ctx, options)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if options.DryRun {
		writeResetPlan(stdout, result)
	}
	return 0
}

func (a App) runDoctor(ctx context.Context, repair bool, stdout, stderr io.Writer) int {
	if a.doctor == nil {
		fmt.Fprintln(stderr, "envvault: command \"doctor\" is not implemented yet")
		return 2
	}
	var result doctorpkg.Result
	var err error
	if repair {
		repairer, ok := a.doctor.(DoctorRepairer)
		if !ok {
			fmt.Fprintln(stderr, clerr.New(clerr.ConfigInvalid, "doctor repair is unavailable"))
			return 1
		}
		result, err = repairer.Repair(ctx)
	} else {
		result, err = a.doctor.Check(ctx)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	writeDoctorResult(stdout, result)
	if result.HasErrors() {
		return 1
	}
	return 0
}

func (a App) runProfileAddProcess(ctx context.Context, request profilemgr.ProcessRequest, stderr io.Writer) int {
	if a.profileManager == nil {
		fmt.Fprintln(stderr, "envvault: command \"profile\" is not implemented yet")
		return 2
	}
	binding, err := a.approveProjectBinding(ctx, request.ProjectBinding.Mode)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	request.ProjectBinding = binding
	if _, err := a.profileManager.AddProcess(ctx, request); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func (a App) runProfileAddBrowserSession(ctx context.Context, request profilemgr.BrowserSessionRequest, stderr io.Writer) int {
	if a.profileManager == nil {
		fmt.Fprintln(stderr, "envvault: command \"profile\" is not implemented yet")
		return 2
	}
	binding, err := a.approveProjectBinding(ctx, request.ProjectBinding.Mode)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	request.ProjectBinding = binding
	if _, err := a.profileManager.AddBrowserSession(ctx, request); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func (a App) runSecretAdd(ctx context.Context, name string, stderr io.Writer) int {
	if a.secrets == nil {
		fmt.Fprintln(stderr, clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable"))
		return 1
	}
	input := a.stdin
	if input == nil {
		input = os.Stdin
	}
	raw, err := io.ReadAll(input)
	if err != nil {
		fmt.Fprintln(stderr, clerr.Wrap(clerr.ConfigInvalid, "read api key from stdin", err))
		return 1
	}
	apiKey := strings.TrimSpace(string(raw))
	if strings.TrimSpace(apiKey) == "" {
		fmt.Fprintln(stderr, clerr.New(clerr.ConfigInvalid, "api key is required"))
		return 1
	}
	secret := []byte(apiKey)
	defer zero(secret)
	if err := a.secrets.Put(ctx, keyring.CredentialValue(name), secret); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := a.recordCredentialName(name); err != nil {
		_ = a.secrets.Delete(ctx, keyring.CredentialValue(name))
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func (a App) runCredentialSetFromStdin(ctx context.Context, name string, stderr io.Writer) int {
	if a.secrets == nil {
		fmt.Fprintln(stderr, clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable"))
		return 1
	}
	input := a.stdin
	if input == nil {
		input = os.Stdin
	}
	raw, err := io.ReadAll(input)
	if err != nil {
		fmt.Fprintln(stderr, clerr.Wrap(clerr.ConfigInvalid, "read credential from stdin", err))
		return 1
	}
	defer zero(raw)
	value := bytes.TrimSpace(raw)
	if len(value) == 0 {
		fmt.Fprintln(stderr, clerr.New(clerr.ConfigInvalid, "credential value is required"))
		return 1
	}
	return a.storeCredential(ctx, name, value, stderr)
}

func (a App) runCredentialSetInteractive(ctx context.Context, name string, stderr io.Writer) int {
	if a.secrets == nil {
		fmt.Fprintln(stderr, clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable"))
		return 1
	}
	if a.credentialReader == nil {
		fmt.Fprintln(stderr, clerr.New(clerr.ConfigInvalid, "interactive credential input unavailable; use envvault credential set <name> --value-stdin"))
		return 1
	}
	raw, err := a.credentialReader(stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer zero(raw)
	value := bytes.TrimSpace(raw)
	if len(value) == 0 {
		fmt.Fprintln(stderr, clerr.New(clerr.ConfigInvalid, "credential value is required"))
		return 1
	}
	return a.storeCredential(ctx, name, value, stderr)
}

func (a App) storeCredential(ctx context.Context, name string, value []byte, stderr io.Writer) int {
	if err := a.secrets.Put(ctx, keyring.CredentialValue(name), value); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := a.recordCredentialName(name); err != nil {
		_ = a.secrets.Delete(ctx, keyring.CredentialValue(name))
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func (a App) runCredentialDelete(ctx context.Context, name string, cascade bool, stderr io.Writer) int {
	if a.secrets == nil {
		fmt.Fprintln(stderr, clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable"))
		return 1
	}
	cfg, err := config.LoadOrDefault(a.paths.ConfigFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	name = strings.TrimSpace(name)
	if !cfg.RemoveCredential(name) {
		fmt.Fprintln(stderr, clerr.New(clerr.ConfigInvalid, "credential not found"))
		return 1
	}
	referencingProfiles := profilesUsingCredential(cfg, name)
	if len(referencingProfiles) > 0 && !cascade {
		fmt.Fprintln(stderr, clerr.New(clerr.ConfigInvalid, "credential is used by profiles: "+strings.Join(referencingProfiles, ", ")+"; pass --cascade to delete them too"))
		return 1
	}

	value, err := a.secrets.Get(ctx, keyring.CredentialValue(name))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer zero(value)
	if err := a.secrets.Delete(ctx, keyring.CredentialValue(name)); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
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
		fmt.Fprintln(stderr, err)
		return 1
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
		fmt.Fprintln(stderr, err)
		return 1
	}
	rows := make([][]string, 0, len(cfg.CredentialNames()))
	for _, name := range cfg.CredentialNames() {
		rows = append(rows, []string{name})
	}
	if err := writeTable(stdout, []string{"NAME"}, rows); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func (a App) runProfileList(stdout, stderr io.Writer) int {
	return a.writeProfileList(stdout, stderr, nil, []string{"NAME", "KIND", "CREDENTIAL", "TARGET", "BINDING"})
}

func (a App) runProxyList(stdout, stderr io.Writer) int {
	return a.writeProfileList(stdout, stderr, func(stored config.Profile) bool {
		return stored.Kind == profile.KindProviderProxy
	}, []string{"NAME", "CREDENTIAL", "TARGET", "BINDING"})
}

func (a App) writeProfileList(stdout, stderr io.Writer, include func(config.Profile) bool, header []string) int {
	cfg, err := config.LoadOrDefault(a.paths.ConfigFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
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
		if len(header) == 4 {
			rows = append(rows, []string{
				name,
				stored.CredentialName,
				listTarget(stored),
				listProjectBinding(stored.ProjectBinding.Mode),
			})
			continue
		}
		rows = append(rows, []string{
			name,
			string(stored.Kind),
			stored.CredentialName,
			listTarget(stored),
			listProjectBinding(stored.ProjectBinding.Mode),
		})
	}
	if err := writeTable(stdout, header, rows); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
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
		fmt.Fprintln(stderr, err)
		return 1
	}
	request.ProjectBinding = binding

	cfg, err := config.LoadOrDefault(a.paths.ConfigFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if _, exists := cfg.Profiles[request.Name]; exists {
		fmt.Fprintln(stderr, clerr.New(clerr.ConfigInvalid, "profile already exists"))
		return 1
	}
	stored := config.Profile{
		Kind:           profile.KindProviderProxy,
		CredentialName: request.CredentialName,
		AuthMode:       request.AuthMode,
		Provider:       request.Provider,
		TargetURL:      request.TargetURL,
		AllowedPaths:   append([]string(nil), request.AllowedPaths...),
		AllowedMethods: append([]string(nil), request.AllowedMethods...),
		LocalTokenTTL:  config.Duration(request.LocalTokenTTL),
		ProjectBinding: toConfigProjectBinding(request.ProjectBinding),
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]config.Profile{}
	}
	cfg.Profiles[request.Name] = stored
	if err := config.Save(a.paths.ConfigFile, cfg); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "Add this to your .env:")
	fmt.Fprint(stdout, envref.ProxyDotenv(request.Name))
	return 0
}

func (a App) runInjectAdd(ctx context.Context, request injectAddRequest, stderr io.Writer) int {
	binding, err := a.approveProjectBinding(ctx, request.ProjectBinding.Mode)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	request.ProjectBinding = binding

	cfg, err := config.LoadOrDefault(a.paths.ConfigFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if _, exists := cfg.Profiles[request.Name]; exists {
		fmt.Fprintln(stderr, clerr.New(clerr.ConfigInvalid, "profile already exists"))
		return 1
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]config.Profile{}
	}
	cfg.Profiles[request.Name] = config.Profile{
		Kind:           profile.KindInject,
		CredentialName: request.CredentialName,
		ProjectBinding: toConfigProjectBinding(request.ProjectBinding),
	}
	if err := config.Save(a.paths.ConfigFile, cfg); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
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
		fmt.Fprintln(stderr, "envvault: command \"admin\" is not implemented yet")
		return 2
	}
	if request.Token == "" && request.TokenEnv != "" {
		request.Token = strings.TrimSpace(os.Getenv(request.TokenEnv))
		if request.Token == "" {
			fmt.Fprintln(stderr, clerr.New(clerr.ConfigInvalid, "admin token env is empty"))
			return 1
		}
	}
	if request.Token == "" {
		tokenSource := a.adminTokenSource
		if tokenSource == nil {
			tokenSource = admin.NewToken
		}
		token, err := tokenSource()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		request.Token = token
	}
	request.Stdout = stdout
	if err := a.adminServer.Serve(ctx, request); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func (a App) runAdminStart(ctx context.Context, request admin.StartRequest, stdout, stderr io.Writer) int {
	if a.adminController == nil {
		fmt.Fprintln(stderr, "envvault: command \"admin\" is not implemented yet")
		return 2
	}
	state, err := a.adminController.Start(ctx, request)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "EnvVault admin: %s\n", state.URL)
	return 0
}

func (a App) runAdminStatus(ctx context.Context, stdout, stderr io.Writer) int {
	if a.adminController == nil {
		fmt.Fprintln(stderr, "envvault: command \"admin\" is not implemented yet")
		return 2
	}
	status, err := a.adminController.Status(ctx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
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
		fmt.Fprintln(stderr, "envvault: command \"admin\" is not implemented yet")
		return 2
	}
	state, err := a.adminController.Stop(ctx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
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
		fmt.Fprintln(stderr, "envvault: command \"token\" is not implemented yet")
		return 2
	}
	if a.tokenOutputToTerminal() && !parsed.allowTTY && !parsed.quiet {
		fmt.Fprintln(stderr, clerr.New(clerr.ConfigInvalid, "token output to a terminal requires --allow-tty or --quiet"))
		return 1
	}
	p, err := a.profiles.Profile(parsed.profile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if p.Kind != profile.KindProcess {
		fmt.Fprintln(stderr, clerr.New(clerr.ProfileKindMismatch, p.Name))
		return 1
	}
	projectIdentity, err := a.detectProjectIdentity(ctx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := projectbinding.Check(p.ProjectBinding, projectIdentity); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	claims, err := process.ProcessClaims(p, projectIdentity)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	credential, err := a.issuer.Issue(ctx, issuer.Grant{
		Profile:  p.Name,
		Resource: p.Resource,
		Scopes:   append([]string(nil), p.Scopes...),
		TTL:      p.TokenTTL,
		Claims:   claims,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
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
		fmt.Fprintln(stderr, err)
		return 1
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
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if !a.execConfigured() {
		fmt.Fprintln(stderr, "envvault: command \"exec\" is not implemented yet")
		return 2
	}
	parentEnvironment := a.parentEnvironment()
	homeFileSourceDir := ""
	var err error
	if homefile.RequiresSourceDir(parsed.homeFiles) {
		homeFileSourceDir, err = a.homeFileSourceDir()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	projectIdentity, err := a.detectProjectIdentity(ctx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	refResolver := &providerproxy.EnvResolver{
		Profiles: a.profiles,
		Secrets:  a.secrets,
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = refResolver.Close(shutdownCtx)
	}()
	env, err := process.BuildEnv(ctx, process.EnvInput{
		Parent:            parentEnvironment,
		EnvFiles:          parsed.envFiles,
		InlineEnv:         parsed.inlineEnv,
		ProjectIdentity:   projectIdentity,
		ReferenceResolver: refResolver,
	}, a.profiles, a.issuer)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
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
			fmt.Fprintln(stderr, err)
			return 1
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
	start := a.projectStartDir
	if start == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", clerr.Wrap(clerr.ConfigInvalid, "get current directory for --home-file", err)
		}
		start = cwd
	}
	absolute, err := filepath.Abs(start)
	if err != nil {
		return "", clerr.Wrap(clerr.ConfigInvalid, "resolve current directory for --home-file", err)
	}
	return filepath.Clean(absolute), nil
}

func (a App) detectProjectIdentity(ctx context.Context) (projectbinding.Identity, error) {
	start := a.projectStartDir
	if start == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return projectbinding.Identity{}, clerr.Wrap(clerr.ConfigInvalid, "get current directory", err)
		}
		start = cwd
	}
	return projectbinding.Detect(ctx, start)
}

func (a App) runOpen(ctx context.Context, parsed openArgs, stdout, stderr io.Writer) int {
	if !a.openConfigured() {
		fmt.Fprintln(stderr, "envvault: command \"open\" is not implemented yet")
		return 2
	}
	p, err := a.profiles.Profile(parsed.profile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if p.Kind != profile.KindBrowserSession {
		fmt.Fprintln(stderr, clerr.New(clerr.ProfileKindMismatch, p.Name))
		return 1
	}
	projectIdentity, err := a.detectProjectIdentity(ctx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := projectbinding.Check(p.ProjectBinding, projectIdentity); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	result, err := a.browser.Open(ctx, browser.OpenRequest{
		Profile:         p,
		Browser:         parsed.browser,
		PrintURL:        parsed.printURL,
		ProjectIdentity: projectIdentity,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
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

func toConfigProjectBinding(binding profile.ProjectBinding) config.ProjectBinding {
	return config.ProjectBinding{
		Mode:      binding.Mode,
		PathHash:  binding.PathHash,
		GitRoot:   binding.GitRoot,
		GitRemote: binding.GitRemote,
	}
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
		fmt.Fprintln(stderr, clerr.Wrap(clerr.ConfigInvalid, "read jwks file", err))
		return 1
	}
	if _, err := stdout.Write(body); err != nil {
		fmt.Fprintln(stderr, clerr.Wrap(clerr.ConfigInvalid, "write jwks", err))
		return 1
	}
	if len(body) == 0 || body[len(body)-1] != '\n' {
		if _, err := fmt.Fprintln(stdout); err != nil {
			fmt.Fprintln(stderr, clerr.Wrap(clerr.ConfigInvalid, "write jwks newline", err))
			return 1
		}
	}
	return 0
}

func (a App) runJWKSExport(output string, stderr io.Writer) int {
	body, err := os.ReadFile(a.jwksPath())
	if err != nil {
		fmt.Fprintln(stderr, clerr.Wrap(clerr.ConfigInvalid, "read jwks file", err))
		return 1
	}
	if err := jwks.Export(output, body); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func (a App) runIssuerShow(stdout, stderr io.Writer) int {
	cfg, err := config.Load(a.paths.ConfigFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
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
