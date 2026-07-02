package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
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

type Options struct {
	Paths                   config.Paths
	Initializer             Initializer
	Resetter                Resetter
	Doctor                  Doctor
	Secrets                 keyring.Store
	Stdin                   io.Reader
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
		Paths:          paths,
		Initializer:    managedTalos,
		Secrets:        secrets,
		Profiles:       profiles,
		Issuer:         tokenIssuer,
		Runner:         process.Runner{},
		Browser:        browser.Client{Issuer: tokenIssuer, Opener: browser.CommandOpener{}, Audit: auditRecorder},
		ProfileManager: profilemgr.New(paths.ConfigFile, secrets, managedTalos),
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
	if len(args) == 0 {
		fmt.Fprintln(stderr, "envvault: command required")
		return 2
	}
	if target, ok := helpTarget(args); ok {
		return writeHelp(target, stdout, stderr)
	}

	switch args[0] {
	case "init":
		return a.runInit(ctx, args[1:], stdout, stderr)
	case "reset":
		return a.runReset(ctx, args[1:], stdout, stderr)
	case "doctor":
		return a.runDoctor(ctx, args[1:], stdout, stderr)
	case "profile":
		return a.runProfile(ctx, args[1:], stdout, stderr)
	case "credential":
		return a.runCredential(ctx, args[1:], stdout, stderr)
	case "secret":
		return a.runSecret(ctx, args[1:], stdout, stderr)
	case "proxy":
		return a.runProxy(ctx, args[1:], stdout, stderr)
	case "inject":
		return a.runInject(ctx, args[1:], stdout, stderr)
	case "list":
		return a.runList(args[1:], stdout, stderr)
	case "admin":
		return a.runAdmin(ctx, args[1:], stdout, stderr)
	case "token":
		return a.runToken(ctx, args[1:], stdout, stderr)
	case "exec":
		return a.runExec(ctx, args[1:], stdout, stderr)
	case "open":
		return a.runOpen(ctx, args[1:], stdout, stderr)
	case "jwks":
		return a.runJWKS(args[1:], stdout, stderr)
	case "issuer":
		return a.runIssuer(ctx, args[1:], stdout, stderr)
	case "completion":
		return a.runCompletion(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "envvault: command %q is not implemented yet\n", args[0])
		return 2
	}
}

func (a App) runInit(ctx context.Context, args []string, _ io.Writer, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "envvault: usage: envvault init")
		return 2
	}
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

func (a App) runReset(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if a.resetter == nil {
		fmt.Fprintln(stderr, "envvault: command \"reset\" is not implemented yet")
		return 2
	}
	options, confirmed, err := parseResetArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
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

func (a App) runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	repair, err := parseDoctorArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, "envvault: usage: envvault doctor")
		return 2
	}
	if a.doctor == nil {
		fmt.Fprintln(stderr, "envvault: command \"doctor\" is not implemented yet")
		return 2
	}
	var result doctorpkg.Result
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

func (a App) runProfile(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "list" {
		return a.runProfileList(stdout, stderr)
	}
	if a.profileManager == nil {
		fmt.Fprintln(stderr, "envvault: command \"profile\" is not implemented yet")
		return 2
	}
	if len(args) < 2 || args[0] != "add" {
		fmt.Fprintln(stderr, "envvault: usage: envvault profile add <kind> <name> [options]")
		return 2
	}

	switch args[1] {
	case string(profile.KindProcess):
		request, err := parseProfileAddProcess(args[2:])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
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
	case string(profile.KindBrowserSession):
		request, err := parseProfileAddBrowserSession(args[2:])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
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
	default:
		fmt.Fprintf(stderr, "envvault: profile kind %q is not implemented yet\n", args[1])
		return 2
	}
}

func (a App) runSecret(ctx context.Context, args []string, _ io.Writer, stderr io.Writer) int {
	if len(args) < 2 || args[0] != "add" {
		fmt.Fprintln(stderr, "envvault: usage: envvault secret add <name> --provider openai-compatible --api-key-stdin")
		return 2
	}
	if a.secrets == nil {
		fmt.Fprintln(stderr, clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable"))
		return 1
	}
	request, err := parseSecretAdd(args[1:])
	if err != nil {
		fmt.Fprintln(stderr, err)
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
	if err := a.secrets.Put(ctx, keyring.CredentialValue(request.Name), secret); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := a.recordCredentialName(request.Name); err != nil {
		_ = a.secrets.Delete(ctx, keyring.CredentialValue(request.Name))
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func (a App) runCredential(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "list" {
		return a.runCredentialList(stdout, stderr)
	}
	if len(args) < 2 || args[0] != "add" {
		fmt.Fprintln(stderr, "envvault: usage: envvault credential add <name> --value-stdin")
		return 2
	}
	if a.secrets == nil {
		fmt.Fprintln(stderr, clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable"))
		return 1
	}
	request, err := parseCredentialAdd(args[1:])
	if err != nil {
		fmt.Fprintln(stderr, err)
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
	value := []byte(strings.TrimSpace(string(raw)))
	defer zero(value)
	if len(value) == 0 {
		fmt.Fprintln(stderr, clerr.New(clerr.ConfigInvalid, "credential value is required"))
		return 1
	}
	if err := a.secrets.Put(ctx, keyring.CredentialValue(request.Name), value); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := a.recordCredentialName(request.Name); err != nil {
		_ = a.secrets.Delete(ctx, keyring.CredentialValue(request.Name))
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func (a App) runList(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "envvault: usage: envvault list <credentials|profiles>")
		return 2
	}
	switch args[0] {
	case "credential", "credentials":
		return a.runCredentialList(stdout, stderr)
	case "profile", "profiles":
		return a.runProfileList(stdout, stderr)
	default:
		fmt.Fprintln(stderr, "envvault: usage: envvault list <credentials|profiles>")
		return 2
	}
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
		rows = append(rows, []string{
			name,
			string(stored.Kind),
			stored.CredentialName,
			listTarget(stored),
			listProjectBinding(stored.ProjectBinding.Mode),
		})
	}
	if err := writeTable(stdout, []string{"NAME", "KIND", "CREDENTIAL", "TARGET", "BINDING"}, rows); err != nil {
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

func (a App) runProxy(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) < 2 || args[0] != "add" {
		fmt.Fprintln(stderr, "envvault: usage: envvault proxy add <name> [options]")
		return 2
	}
	request, err := parseProxyAdd(args[1:])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
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

func (a App) runInject(ctx context.Context, args []string, _ io.Writer, stderr io.Writer) int {
	if len(args) < 2 || args[0] != "add" {
		fmt.Fprintln(stderr, "envvault: usage: envvault inject add <name> --credential <credential> [options]")
		return 2
	}
	request, err := parseInjectAdd(args[1:])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
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

func (a App) runAdmin(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "envvault: usage: envvault admin <start|status|stop|serve>")
		return 2
	}
	switch args[0] {
	case "serve":
		return a.runAdminServe(ctx, args[1:], stdout, stderr)
	case "start":
		return a.runAdminStart(ctx, args[1:], stdout, stderr)
	case "status":
		return a.runAdminStatus(ctx, args[1:], stdout, stderr)
	case "stop":
		return a.runAdminStop(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "envvault: usage: envvault admin <start|status|stop|serve>")
		return 2
	}
}

func (a App) runAdminServe(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if a.adminServer == nil {
		fmt.Fprintln(stderr, "envvault: command \"admin\" is not implemented yet")
		return 2
	}
	request, err := parseAdminServe(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
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

func (a App) runAdminStart(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if a.adminController == nil {
		fmt.Fprintln(stderr, "envvault: command \"admin\" is not implemented yet")
		return 2
	}
	request, err := parseAdminStart(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	state, err := a.adminController.Start(ctx, request)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "EnvVault admin: %s\n", state.URL)
	return 0
}

func (a App) runAdminStatus(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "envvault: usage: envvault admin status")
		return 2
	}
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

func (a App) runAdminStop(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "envvault: usage: envvault admin stop")
		return 2
	}
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

func (a App) runToken(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if !a.tokenConfigured() {
		fmt.Fprintln(stderr, "envvault: command \"token\" is not implemented yet")
		return 2
	}

	parsed, err := parseTokenArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
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

func (a App) runExec(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if !a.execConfigured() {
		if err := validateInlineEnvReferences(args); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}

		fmt.Fprintln(stderr, "envvault: command \"exec\" is not implemented yet")
		return 2
	}

	parsed, err := parseExecArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	projectIdentity, err := a.detectProjectIdentity(ctx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	refResolver := &providerproxy.EnvResolver{
		Profiles: a.profiles,
		Secrets:  a.secrets,
		Issuer:   a.issuer,
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = refResolver.Close(shutdownCtx)
	}()
	env, err := process.BuildEnv(ctx, process.EnvInput{
		Parent:            a.parentEnvironment(),
		EnvFiles:          parsed.envFiles,
		InlineEnv:         parsed.inlineEnv,
		ProjectIdentity:   projectIdentity,
		ReferenceResolver: refResolver,
	}, a.profiles, a.issuer)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
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
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return code
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

func (a App) runOpen(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if !a.openConfigured() {
		fmt.Fprintln(stderr, "envvault: command \"open\" is not implemented yet")
		return 2
	}

	parsed, err := parseOpenArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
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
	return a.profiles != nil && a.issuer != nil && a.runner != nil
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

func (a App) runJWKS(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "envvault: jwks subcommand required")
		return 2
	}

	switch args[0] {
	case "show":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "envvault: usage: envvault jwks show")
			return 2
		}
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
	case "export":
		output, err := parseOutputPath(args[1:])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
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
	default:
		fmt.Fprintf(stderr, "envvault: jwks subcommand %q is not implemented yet\n", args[0])
		return 2
	}
}

func (a App) runIssuer(_ context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "show" {
		fmt.Fprintln(stderr, "envvault: usage: envvault issuer show")
		return 2
	}

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

func parseOutputPath(args []string) (string, error) {
	if len(args) == 0 {
		return "", clerr.New(clerr.ConfigInvalid, "jwks export requires --output")
	}
	if len(args) > 2 {
		return "", clerr.New(clerr.ConfigInvalid, "too many jwks export arguments")
	}
	if args[0] == "--output" {
		if len(args) != 2 || strings.TrimSpace(args[1]) == "" {
			return "", clerr.New(clerr.ConfigInvalid, "--output requires a path")
		}
		return args[1], nil
	}
	if strings.HasPrefix(args[0], "--output=") {
		if len(args) != 1 {
			return "", clerr.New(clerr.ConfigInvalid, "too many jwks export arguments")
		}
		output := strings.TrimPrefix(args[0], "--output=")
		if strings.TrimSpace(output) == "" {
			return "", clerr.New(clerr.ConfigInvalid, "--output requires a path")
		}
		return output, nil
	}
	return "", clerr.New(clerr.ConfigInvalid, "jwks export requires --output")
}

func parseResetArgs(args []string) (resetpkg.Options, bool, error) {
	var options resetpkg.Options
	confirmed := false
	for _, arg := range args {
		switch arg {
		case "--dry-run":
			options.DryRun = true
		case "--yes":
			confirmed = true
		default:
			return resetpkg.Options{}, false, clerr.New(clerr.ConfigInvalid, "unknown reset option")
		}
	}
	return options, confirmed, nil
}

func parseDoctorArgs(args []string) (bool, error) {
	switch len(args) {
	case 0:
		return false, nil
	case 1:
		if args[0] == "--repair" {
			return true, nil
		}
	}
	return false, clerr.New(clerr.ConfigInvalid, "unknown doctor option")
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

func parseProfileAddProcess(args []string) (profilemgr.ProcessRequest, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return profilemgr.ProcessRequest{}, clerr.New(clerr.ConfigInvalid, "profile name is required")
	}
	request := profilemgr.ProcessRequest{
		Name: args[0],
		ProjectBinding: profile.ProjectBinding{
			Mode: profile.ProjectBindingGitRemoteAndRoot,
		},
	}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--resource":
			value, next, err := valueFlag(args, i, "--resource")
			if err != nil {
				return profilemgr.ProcessRequest{}, err
			}
			request.Resource = value
			i = next
		case "--scope":
			value, next, err := valueFlag(args, i, "--scope")
			if err != nil {
				return profilemgr.ProcessRequest{}, err
			}
			request.Scopes = append(request.Scopes, value)
			i = next
		case "--ttl":
			value, next, err := durationFlag(args, i, "--ttl")
			if err != nil {
				return profilemgr.ProcessRequest{}, err
			}
			request.TokenTTL = value
			i = next
		case "--max-ttl":
			value, next, err := durationFlag(args, i, "--max-ttl")
			if err != nil {
				return profilemgr.ProcessRequest{}, err
			}
			request.MaxTokenTTL = value
			i = next
		case "--project-binding":
			value, next, err := projectBindingFlag(args, i)
			if err != nil {
				return profilemgr.ProcessRequest{}, err
			}
			request.ProjectBinding = value
			i = next
		default:
			return profilemgr.ProcessRequest{}, clerr.New(clerr.ConfigInvalid, "unknown process profile option")
		}
	}
	if request.Resource == "" {
		return profilemgr.ProcessRequest{}, clerr.New(clerr.ConfigInvalid, "--resource is required")
	}
	if len(request.Scopes) == 0 {
		return profilemgr.ProcessRequest{}, clerr.New(clerr.ConfigInvalid, "--scope is required")
	}
	if request.TokenTTL <= 0 {
		return profilemgr.ProcessRequest{}, clerr.New(clerr.ConfigInvalid, "--ttl is required")
	}
	if request.MaxTokenTTL <= 0 {
		return profilemgr.ProcessRequest{}, clerr.New(clerr.ConfigInvalid, "--max-ttl is required")
	}
	return request, nil
}

func parseProfileAddBrowserSession(args []string) (profilemgr.BrowserSessionRequest, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return profilemgr.BrowserSessionRequest{}, clerr.New(clerr.ConfigInvalid, "profile name is required")
	}
	request := profilemgr.BrowserSessionRequest{
		Name: args[0],
		ProjectBinding: profile.ProjectBinding{
			Mode: profile.ProjectBindingGitRemoteAndRoot,
		},
	}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--resource":
			value, next, err := valueFlag(args, i, "--resource")
			if err != nil {
				return profilemgr.BrowserSessionRequest{}, err
			}
			request.Resource = value
			i = next
		case "--exchange-url":
			value, next, err := valueFlag(args, i, "--exchange-url")
			if err != nil {
				return profilemgr.BrowserSessionRequest{}, err
			}
			request.ExchangeURL = value
			i = next
		case "--complete-url":
			value, next, err := valueFlag(args, i, "--complete-url")
			if err != nil {
				return profilemgr.BrowserSessionRequest{}, err
			}
			request.CompleteURL = value
			i = next
		case "--post-login-url":
			value, next, err := valueFlag(args, i, "--post-login-url")
			if err != nil {
				return profilemgr.BrowserSessionRequest{}, err
			}
			request.PostLoginURL = value
			i = next
		case "--scope":
			value, next, err := valueFlag(args, i, "--scope")
			if err != nil {
				return profilemgr.BrowserSessionRequest{}, err
			}
			request.Scopes = append(request.Scopes, value)
			i = next
		case "--bootstrap-ttl":
			value, next, err := durationFlag(args, i, "--bootstrap-ttl")
			if err != nil {
				return profilemgr.BrowserSessionRequest{}, err
			}
			request.BootstrapTokenTTL = value
			i = next
		case "--code-ttl":
			value, next, err := durationFlag(args, i, "--code-ttl")
			if err != nil {
				return profilemgr.BrowserSessionRequest{}, err
			}
			request.LoginCodeTTL = value
			i = next
		case "--session-ttl":
			value, next, err := durationFlag(args, i, "--session-ttl")
			if err != nil {
				return profilemgr.BrowserSessionRequest{}, err
			}
			request.WebSessionTTL = value
			i = next
		case "--allowed-host":
			value, next, err := valueFlag(args, i, "--allowed-host")
			if err != nil {
				return profilemgr.BrowserSessionRequest{}, err
			}
			request.AllowedHosts = append(request.AllowedHosts, value)
			i = next
		case "--project-binding":
			value, next, err := projectBindingFlag(args, i)
			if err != nil {
				return profilemgr.BrowserSessionRequest{}, err
			}
			request.ProjectBinding = value
			i = next
		default:
			return profilemgr.BrowserSessionRequest{}, clerr.New(clerr.ConfigInvalid, "unknown browser-session profile option")
		}
	}
	if request.Resource == "" {
		return profilemgr.BrowserSessionRequest{}, clerr.New(clerr.ConfigInvalid, "--resource is required")
	}
	if len(request.Scopes) == 0 {
		return profilemgr.BrowserSessionRequest{}, clerr.New(clerr.ConfigInvalid, "--scope is required")
	}
	if request.ExchangeURL == "" || request.CompleteURL == "" || request.PostLoginURL == "" {
		return profilemgr.BrowserSessionRequest{}, clerr.New(clerr.ConfigInvalid, "browser-session urls are required")
	}
	if request.BootstrapTokenTTL <= 0 || request.LoginCodeTTL <= 0 || request.WebSessionTTL <= 0 {
		return profilemgr.BrowserSessionRequest{}, clerr.New(clerr.ConfigInvalid, "browser-session ttls are required")
	}
	if len(request.AllowedHosts) == 0 {
		host, err := hostFromURL(request.Resource)
		if err != nil {
			return profilemgr.BrowserSessionRequest{}, err
		}
		request.AllowedHosts = []string{host}
	}
	return request, nil
}

type secretAddRequest struct {
	Name        string
	Provider    string
	APIKeyStdin bool
}

type credentialAddRequest struct {
	Name       string
	ValueStdin bool
}

func parseCredentialAdd(args []string) (credentialAddRequest, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return credentialAddRequest{}, clerr.New(clerr.ConfigInvalid, "credential name is required")
	}
	request := credentialAddRequest{Name: args[0]}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--value-stdin":
			request.ValueStdin = true
		default:
			return credentialAddRequest{}, clerr.New(clerr.ConfigInvalid, "unknown credential option")
		}
	}
	if !request.ValueStdin {
		return credentialAddRequest{}, clerr.New(clerr.ConfigInvalid, "credential value input is required")
	}
	return request, nil
}

func parseSecretAdd(args []string) (secretAddRequest, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return secretAddRequest{}, clerr.New(clerr.ConfigInvalid, "secret name is required")
	}
	request := secretAddRequest{Name: args[0]}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--provider":
			value, next, err := valueFlag(args, i, "--provider")
			if err != nil {
				return secretAddRequest{}, err
			}
			request.Provider = value
			i = next
		case "--api-key-stdin":
			request.APIKeyStdin = true
		default:
			return secretAddRequest{}, clerr.New(clerr.ConfigInvalid, "unknown secret option")
		}
	}
	if request.Provider != "openai-compatible" {
		return secretAddRequest{}, clerr.New(clerr.ConfigInvalid, "provider must be openai-compatible")
	}
	if !request.APIKeyStdin {
		return secretAddRequest{}, clerr.New(clerr.ConfigInvalid, "api key input is required")
	}
	return request, nil
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

func parseProxyAdd(args []string) (proxyAddRequest, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return proxyAddRequest{}, clerr.New(clerr.ConfigInvalid, "proxy profile name is required")
	}
	request := proxyAddRequest{
		Name:          args[0],
		AuthMode:      "bearer",
		LocalTokenTTL: 10 * time.Minute,
		ProjectBinding: profile.ProjectBinding{
			Mode: profile.ProjectBindingGitRemoteAndRoot,
		},
	}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--provider":
			value, next, err := valueFlag(args, i, "--provider")
			if err != nil {
				return proxyAddRequest{}, err
			}
			request.Provider = value
			i = next
		case "--credential":
			value, next, err := valueFlag(args, i, "--credential")
			if err != nil {
				return proxyAddRequest{}, err
			}
			request.CredentialName = value
			i = next
		case "--auth":
			value, next, err := valueFlag(args, i, "--auth")
			if err != nil {
				return proxyAddRequest{}, err
			}
			request.AuthMode = value
			i = next
		case "--target":
			value, next, err := valueFlag(args, i, "--target")
			if err != nil {
				return proxyAddRequest{}, err
			}
			request.TargetURL = value
			i = next
		case "--allow-path":
			value, next, err := valueFlag(args, i, "--allow-path")
			if err != nil {
				return proxyAddRequest{}, err
			}
			request.AllowedPaths = append(request.AllowedPaths, value)
			i = next
		case "--allow-method":
			value, next, err := valueFlag(args, i, "--allow-method")
			if err != nil {
				return proxyAddRequest{}, err
			}
			request.AllowedMethods = append(request.AllowedMethods, strings.ToUpper(value))
			i = next
		case "--token-ttl":
			value, next, err := durationFlag(args, i, "--token-ttl")
			if err != nil {
				return proxyAddRequest{}, err
			}
			request.LocalTokenTTL = value
			i = next
		case "--project-binding":
			value, next, err := projectBindingFlag(args, i)
			if err != nil {
				return proxyAddRequest{}, err
			}
			request.ProjectBinding = value
			i = next
		default:
			return proxyAddRequest{}, clerr.New(clerr.ConfigInvalid, "unknown proxy option")
		}
	}
	if request.Provider == "" {
		request.Provider = "generic"
	}
	if request.Provider != "generic" && request.Provider != "openai-compatible" {
		return proxyAddRequest{}, clerr.New(clerr.ConfigInvalid, "provider must be generic or openai-compatible")
	}
	if request.AuthMode == "" {
		request.AuthMode = "bearer"
	}
	if request.AuthMode != "bearer" {
		return proxyAddRequest{}, clerr.New(clerr.ConfigInvalid, "auth must be bearer")
	}
	if strings.TrimSpace(request.CredentialName) == "" {
		request.CredentialName = request.Name
	}
	if strings.TrimSpace(request.TargetURL) == "" {
		return proxyAddRequest{}, clerr.New(clerr.ConfigInvalid, "--target is required")
	}
	if len(request.AllowedPaths) == 0 {
		request.AllowedPaths = defaultOpenAICompatiblePaths()
	}
	if len(request.AllowedMethods) == 0 {
		request.AllowedMethods = []string{http.MethodPost}
	}
	request.AllowedMethods = uniqueStrings(request.AllowedMethods)
	request.AllowedPaths = uniqueStrings(request.AllowedPaths)
	return request, nil
}

type injectAddRequest struct {
	Name           string
	CredentialName string
	ProjectBinding profile.ProjectBinding
}

func parseInjectAdd(args []string) (injectAddRequest, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return injectAddRequest{}, clerr.New(clerr.ConfigInvalid, "inject profile name is required")
	}
	request := injectAddRequest{
		Name: args[0],
		ProjectBinding: profile.ProjectBinding{
			Mode: profile.ProjectBindingGitRemoteAndRoot,
		},
	}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--credential":
			value, next, err := valueFlag(args, i, "--credential")
			if err != nil {
				return injectAddRequest{}, err
			}
			request.CredentialName = value
			i = next
		case "--project-binding":
			value, next, err := projectBindingFlag(args, i)
			if err != nil {
				return injectAddRequest{}, err
			}
			request.ProjectBinding = value
			i = next
		default:
			return injectAddRequest{}, clerr.New(clerr.ConfigInvalid, "unknown inject option")
		}
	}
	if strings.TrimSpace(request.CredentialName) == "" {
		return injectAddRequest{}, clerr.New(clerr.ConfigInvalid, "--credential is required")
	}
	return request, nil
}

func parseAdminServe(args []string) (admin.ServeRequest, error) {
	request := admin.ServeRequest{Addr: admin.DefaultAddr}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--addr":
			value, next, err := valueFlag(args, i, "--addr")
			if err != nil {
				return admin.ServeRequest{}, err
			}
			request.Addr = value
			i = next
		case "--token":
			value, next, err := valueFlag(args, i, "--token")
			if err != nil {
				return admin.ServeRequest{}, err
			}
			request.Token = value
			i = next
		case "--token-env":
			value, next, err := valueFlag(args, i, "--token-env")
			if err != nil {
				return admin.ServeRequest{}, err
			}
			request.TokenEnv = value
			i = next
		default:
			if strings.HasPrefix(args[i], "--addr=") {
				request.Addr = strings.TrimPrefix(args[i], "--addr=")
				continue
			}
			if strings.HasPrefix(args[i], "--token=") {
				request.Token = strings.TrimPrefix(args[i], "--token=")
				continue
			}
			if strings.HasPrefix(args[i], "--token-env=") {
				request.TokenEnv = strings.TrimPrefix(args[i], "--token-env=")
				continue
			}
			return admin.ServeRequest{}, clerr.New(clerr.ConfigInvalid, "unknown admin option")
		}
	}
	if strings.TrimSpace(request.Addr) == "" {
		return admin.ServeRequest{}, clerr.New(clerr.ConfigInvalid, "--addr requires an address")
	}
	if strings.TrimSpace(request.Token) == "" {
		request.Token = ""
	}
	return request, nil
}

func parseAdminStart(args []string) (admin.StartRequest, error) {
	request := admin.StartRequest{Addr: admin.DefaultAddr}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--addr":
			value, next, err := valueFlag(args, i, "--addr")
			if err != nil {
				return admin.StartRequest{}, err
			}
			request.Addr = value
			i = next
		default:
			if strings.HasPrefix(args[i], "--addr=") {
				request.Addr = strings.TrimPrefix(args[i], "--addr=")
				continue
			}
			return admin.StartRequest{}, clerr.New(clerr.ConfigInvalid, "unknown admin option")
		}
	}
	if strings.TrimSpace(request.Addr) == "" {
		return admin.StartRequest{}, clerr.New(clerr.ConfigInvalid, "--addr requires an address")
	}
	return request, nil
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

func valueFlag(args []string, index int, name string) (string, int, error) {
	index++
	if index >= len(args) || strings.TrimSpace(args[index]) == "" {
		return "", index, clerr.New(clerr.ConfigInvalid, name+" requires a value")
	}
	return args[index], index, nil
}

func durationFlag(args []string, index int, name string) (time.Duration, int, error) {
	raw, next, err := valueFlag(args, index, name)
	if err != nil {
		return 0, next, err
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return 0, next, clerr.Wrap(clerr.ConfigInvalid, "parse "+name, err)
	}
	return parsed, next, nil
}

func projectBindingFlag(args []string, index int) (profile.ProjectBinding, int, error) {
	raw, next, err := valueFlag(args, index, "--project-binding")
	if err != nil {
		return profile.ProjectBinding{}, next, err
	}
	switch profile.ProjectBindingMode(raw) {
	case profile.ProjectBindingNone, profile.ProjectBindingPathHash, profile.ProjectBindingGitRemoteAndRoot:
		return profile.ProjectBinding{Mode: profile.ProjectBindingMode(raw)}, next, nil
	default:
		return profile.ProjectBinding{}, next, clerr.New(clerr.ConfigInvalid, "unknown project binding mode")
	}
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

func parseTokenArgs(args []string) (tokenArgs, error) {
	parsed := tokenArgs{format: tokenout.FormatRaw}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--allow-tty":
			parsed.allowTTY = true
		case arg == "--quiet":
			parsed.quiet = true
		case arg == "--format":
			i++
			if i >= len(args) {
				return tokenArgs{}, clerr.New(clerr.ConfigInvalid, "--format requires raw or json")
			}
			format, err := parseTokenFormat(args[i])
			if err != nil {
				return tokenArgs{}, err
			}
			parsed.format = format
		case strings.HasPrefix(arg, "--format="):
			format, err := parseTokenFormat(strings.TrimPrefix(arg, "--format="))
			if err != nil {
				return tokenArgs{}, err
			}
			parsed.format = format
		case strings.HasPrefix(arg, "-"):
			return tokenArgs{}, clerr.New(clerr.ConfigInvalid, "unknown token option")
		default:
			if parsed.profile != "" {
				return tokenArgs{}, clerr.New(clerr.ConfigInvalid, "token accepts exactly one profile")
			}
			parsed.profile = arg
		}
	}
	if strings.TrimSpace(parsed.profile) == "" {
		return tokenArgs{}, clerr.New(clerr.ConfigInvalid, "token requires a profile")
	}
	return parsed, nil
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
	command   []string
}

type openArgs struct {
	profile  string
	browser  string
	printURL bool
}

func parseOpenArgs(args []string) (openArgs, error) {
	var parsed openArgs
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--print-url":
			parsed.printURL = true
		case arg == "--browser":
			i++
			if i >= len(args) || strings.TrimSpace(args[i]) == "" {
				return openArgs{}, clerr.New(clerr.ConfigInvalid, "--browser requires a browser name")
			}
			parsed.browser = args[i]
		case strings.HasPrefix(arg, "--browser="):
			browserName := strings.TrimPrefix(arg, "--browser=")
			if strings.TrimSpace(browserName) == "" {
				return openArgs{}, clerr.New(clerr.ConfigInvalid, "--browser requires a browser name")
			}
			parsed.browser = browserName
		case strings.HasPrefix(arg, "-"):
			return openArgs{}, clerr.New(clerr.ConfigInvalid, "unknown open option")
		default:
			if parsed.profile != "" {
				return openArgs{}, clerr.New(clerr.ConfigInvalid, "open accepts exactly one profile")
			}
			parsed.profile = arg
		}
	}
	if strings.TrimSpace(parsed.profile) == "" {
		return openArgs{}, clerr.New(clerr.ConfigInvalid, "open requires a profile")
	}
	return parsed, nil
}

func parseExecArgs(args []string) (execArgs, error) {
	var parsed execArgs
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			parsed.command = append([]string(nil), args[i+1:]...)
			if len(parsed.command) == 0 {
				return execArgs{}, clerr.New(clerr.ConfigInvalid, "child command is required")
			}
			return parsed, nil
		}
		switch {
		case arg == "--env-file":
			i++
			if i >= len(args) || strings.TrimSpace(args[i]) == "" {
				return execArgs{}, clerr.New(clerr.ConfigInvalid, "--env-file requires a path")
			}
			parsed.envFiles = append(parsed.envFiles, args[i])
		case strings.HasPrefix(arg, "--env-file="):
			path := strings.TrimPrefix(arg, "--env-file=")
			if strings.TrimSpace(path) == "" {
				return execArgs{}, clerr.New(clerr.ConfigInvalid, "--env-file requires a path")
			}
			parsed.envFiles = append(parsed.envFiles, path)
		case arg == "--env":
			i++
			if i >= len(args) {
				return execArgs{}, clerr.New(clerr.ConfigInvalid, "--env requires KEY=VALUE")
			}
			if err := validateEnvAssignment(args[i]); err != nil {
				return execArgs{}, err
			}
			parsed.inlineEnv = append(parsed.inlineEnv, args[i])
		case strings.HasPrefix(arg, "--env="):
			assignment := strings.TrimPrefix(arg, "--env=")
			if err := validateEnvAssignment(assignment); err != nil {
				return execArgs{}, err
			}
			parsed.inlineEnv = append(parsed.inlineEnv, assignment)
		default:
			return execArgs{}, clerr.New(clerr.ConfigInvalid, "exec arguments must be followed by -- child command")
		}
	}
	return execArgs{}, clerr.New(clerr.ConfigInvalid, "exec requires -- child command")
}

func validateInlineEnvReferences(args []string) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return nil
		}
		if arg == "--env" {
			i++
			if i >= len(args) {
				return clerr.New(clerr.ConfigInvalid, "--env requires KEY=VALUE")
			}
			if err := validateEnvAssignment(args[i]); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(arg, "--env=") {
			if err := validateEnvAssignment(strings.TrimPrefix(arg, "--env=")); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateEnvAssignment(raw string) error {
	key, value, ok := strings.Cut(raw, "=")
	if !ok || key == "" {
		return clerr.New(clerr.ConfigInvalid, "--env requires KEY=VALUE")
	}
	_, _, err := envref.ParseValue(value)
	return err
}
