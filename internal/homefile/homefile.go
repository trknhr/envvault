package homefile

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/keyring"
)

const (
	WorkspacePrefix = "envvault-home-"
	LockFilename    = "active.lock"
)

type Spec struct {
	// Path is slash-separated and relative to the isolated home.
	Path      string
	Source    string
	Format    Format
	Kind      Kind
	Reference envref.Reference
}

type Kind uint8

const (
	KindCredential Kind = iota
	KindTemplate
)

type Format uint8

const (
	FormatJSON Format = iota
	FormatYAML
	FormatTOML
)

func Parse(raw string) (Spec, error) {
	rawPath, rawSource, ok := strings.Cut(raw, "=")
	if !ok {
		destination, err := cleanRelativePath(raw)
		if err != nil {
			return Spec{}, err
		}
		return newTemplateSpec(destination, raw)
	}

	destination, err := cleanRelativePath(rawPath)
	if err != nil {
		return Spec{}, err
	}
	source := strings.TrimSpace(rawSource)
	reference, isReference, err := envref.ParseValue(source)
	if err != nil {
		return Spec{}, err
	}
	if isReference {
		if reference.Part != envref.PartDefault {
			return Spec{}, clerr.New(clerr.ConfigInvalid, "raw --home-file value must be a direct credential reference")
		}
		return Spec{Path: destination, Kind: KindCredential, Reference: reference}, nil
	}
	if strings.Contains(source, "envvault://") {
		return Spec{}, clerr.New(clerr.ConfigInvalid, "EnvVault reference must be the complete --home-file source value")
	}
	return newTemplateSpec(destination, source)
}

func newTemplateSpec(destination, rawSource string) (Spec, error) {
	source, err := cleanTemplateSource(rawSource)
	if err != nil {
		return Spec{}, err
	}
	format, err := inferTemplateFormat(source)
	if err != nil {
		return Spec{}, err
	}
	return Spec{
		Path:   destination,
		Source: source,
		Format: format,
		Kind:   KindTemplate,
	}, nil
}

func ParseAll(values []string) ([]Spec, error) {
	specs := make([]Spec, 0, len(values))
	for _, value := range values {
		spec, err := Parse(value)
		if err != nil {
			return nil, err
		}
		specs = append(specs, spec)
	}
	if err := validateSpecs(specs, runtime.GOOS); err != nil {
		return nil, err
	}
	return specs, nil
}

func validateSpecs(specs []Spec, goos string) error {
	seen := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		cleaned, err := cleanRelativePath(spec.Path)
		if err != nil || cleaned != spec.Path {
			return invalidDestination()
		}
		switch spec.Kind {
		case KindCredential:
			if spec.Source != "" || spec.Format != FormatJSON {
				return clerr.New(clerr.ConfigInvalid, "raw --home-file must not include a template source")
			}
			rawReference := spec.Reference.Raw
			if rawReference == "" {
				rawReference = envref.Format(spec.Reference.Profile, spec.Reference.Part)
			}
			parsed, isReference, err := envref.ParseValue(rawReference)
			if err != nil {
				return err
			}
			if !isReference || parsed.Part != envref.PartDefault || parsed.Profile != spec.Reference.Profile {
				return clerr.New(clerr.ConfigInvalid, "--home-file value must be a direct credential reference")
			}
		case KindTemplate:
			if spec.Reference.Raw != "" || spec.Reference.Profile != "" || spec.Reference.Part != envref.PartDefault {
				return clerr.New(clerr.ConfigInvalid, "template --home-file must not include a direct reference")
			}
			cleanedSource, err := cleanTemplateSource(spec.Source)
			if err != nil || cleanedSource != spec.Source {
				return invalidTemplateSource()
			}
			format, err := inferTemplateFormat(spec.Source)
			if err != nil {
				return err
			}
			if format != spec.Format {
				return clerr.New(clerr.ConfigInvalid, "template format does not match source filename")
			}
		default:
			return clerr.New(clerr.ConfigInvalid, "unknown --home-file source kind")
		}
		key := destinationKey(spec.Path, goos)
		if _, exists := seen[key]; exists {
			return clerr.New(clerr.ConfigInvalid, "duplicate --home-file path")
		}
		for existing := range seen {
			if strings.HasPrefix(key, existing+"/") || strings.HasPrefix(existing, key+"/") {
				return clerr.New(clerr.ConfigInvalid, "--home-file paths must not contain one another")
			}
		}
		seen[key] = struct{}{}
	}
	return nil
}

func RequiresSourceDir(specs []Spec) bool {
	for _, spec := range specs {
		if spec.Kind == KindTemplate && !filepath.IsAbs(spec.Source) {
			return true
		}
	}
	return false
}

func cleanTemplateSource(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || strings.ContainsRune(value, '\x00') {
		return "", invalidTemplateSource()
	}
	if value == "~" || strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`) {
		return "", clerr.New(clerr.ConfigInvalid, "template source does not expand ~; use $HOME")
	}
	cleaned := filepath.Clean(value)
	if cleaned == "." {
		return "", invalidTemplateSource()
	}
	return cleaned, nil
}

func inferTemplateFormat(source string) (Format, error) {
	base := filepath.Base(source)
	extension := strings.ToLower(filepath.Ext(base))
	if extension == base {
		extension = ""
	}
	switch extension {
	case "", ".json":
		return FormatJSON, nil
	case ".yaml", ".yml":
		return FormatYAML, nil
	case ".toml":
		return FormatTOML, nil
	default:
		return 0, clerr.New(clerr.ConfigInvalid, "unsupported --home-file template extension")
	}
}

func invalidTemplateSource() error {
	return clerr.New(clerr.ConfigInvalid, "--home-file template source path is invalid")
}

func cleanRelativePath(raw string) (string, error) {
	portable := strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/")
	if portable == "." || !fs.ValidPath(portable) {
		return "", invalidDestination()
	}
	for _, segment := range strings.Split(portable, "/") {
		if strings.Contains(segment, ":") {
			return "", invalidDestination()
		}
	}
	first, _, _ := strings.Cut(portable, "/")
	if first == "~" {
		return "", clerr.New(clerr.ConfigInvalid, "--home-file path is relative to the isolated home; omit ~")
	}
	localized, err := filepath.Localize(portable)
	if err != nil || !filepath.IsLocal(localized) {
		return "", invalidDestination()
	}
	return portable, nil
}

func destinationKey(destination, goos string) string {
	if goos == "windows" {
		return strings.ToLower(destination)
	}
	return destination
}

func invalidDestination() error {
	return clerr.New(clerr.ConfigInvalid, "--home-file path must stay within the isolated home")
}

type Options struct {
	CacheDir  string
	SourceDir string
	Specs     []Spec
	Secrets   keyring.Store
	GOOS      string
}

type Workspace struct {
	root      string
	home      string
	goos      string
	lock      *workspaceLock
	closeOnce sync.Once
	closeErr  error
}

func Prepare(ctx context.Context, options Options) (*Workspace, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(options.CacheDir) == "" {
		return nil, clerr.New(clerr.ConfigInvalid, "cache directory is required for --home-file")
	}
	if len(options.Specs) == 0 {
		return nil, clerr.New(clerr.ConfigInvalid, "at least one --home-file is required")
	}
	if options.Secrets == nil {
		return nil, clerr.New(clerr.KeyringUnavailable, "home file credential store unavailable")
	}
	if err := validateSpecs(options.Specs, runtime.GOOS); err != nil {
		return nil, err
	}
	if RequiresSourceDir(options.Specs) {
		if strings.TrimSpace(options.SourceDir) == "" || !filepath.IsAbs(options.SourceDir) {
			return nil, clerr.New(clerr.ConfigInvalid, "absolute source directory is required for relative --home-file templates")
		}
	}

	tempDir := filepath.Join(options.CacheDir, "tmp")
	if err := ensurePrivateDirectory(tempDir); err != nil {
		return nil, err
	}
	root, err := os.MkdirTemp(tempDir, WorkspacePrefix)
	if err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "create isolated home workspace", err)
	}
	if err := secureDirectory(root); err != nil {
		var failure error = clerr.Wrap(clerr.ConfigInvalid, "secure isolated home workspace", err)
		if removeErr := os.RemoveAll(root); removeErr != nil {
			failure = errors.Join(failure, clerr.Wrap(clerr.CleanupFailed, "remove isolated home workspace", removeErr))
		}
		return nil, failure
	}
	workspace := &Workspace{
		root: root,
		home: filepath.Join(root, "home"),
		goos: firstNonEmpty(options.GOOS, runtime.GOOS),
	}
	workspace.lock, err = acquireWorkspaceLock(root)
	if err != nil {
		return nil, failPrepare(workspace, err)
	}
	if err := ensurePrivateDirectory(workspace.home); err != nil {
		return nil, failPrepare(workspace, err)
	}

	homeRoot, err := os.OpenRoot(workspace.home)
	if err != nil {
		return nil, failPrepare(workspace, clerr.Wrap(clerr.ConfigInvalid, "open isolated home directory", err))
	}
	resolver := newContentResolver(options.Secrets)
	defer resolver.Close()
	for _, spec := range options.Specs {
		if err := write(ctx, homeRoot, filepath.Clean(options.SourceDir), resolver, spec); err != nil {
			failure := closeRoot(err, homeRoot, "close isolated home directory")
			return nil, failPrepare(workspace, failure)
		}
	}
	if err := homeRoot.Close(); err != nil {
		return nil, failPrepare(workspace, clerr.Wrap(clerr.CleanupFailed, "close isolated home directory", err))
	}
	return workspace, nil
}

func ensurePrivateDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "create isolated home directory", err)
	}
	if err := secureDirectory(directory); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "secure isolated home directory", err)
	}
	return nil
}

func write(ctx context.Context, root *os.Root, sourceDir string, resolver *contentResolver, spec Spec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	localized, err := filepath.Localize(spec.Path)
	if err != nil {
		return invalidDestination()
	}
	parent := path.Dir(spec.Path)
	if parent != "." {
		localizedParent, localizeErr := filepath.Localize(parent)
		if localizeErr != nil {
			return invalidDestination()
		}
		if err := root.MkdirAll(localizedParent, 0o700); err != nil {
			return clerr.Wrap(clerr.ConfigInvalid, "create isolated home directory", err)
		}
	}

	file, err := root.OpenFile(localized, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "create isolated home file", err)
	}
	if err := secureFile(file); err != nil {
		return closeFile(clerr.Wrap(clerr.ConfigInvalid, "secure isolated home file", err), file)
	}
	contents, err := resolver.Materialize(ctx, sourceDir, spec)
	if err != nil {
		return closeFile(err, file)
	}
	defer zero(contents)

	writeErr := writeAll(file, contents)
	closeErr := file.Close()
	if writeErr != nil {
		var failure error = clerr.Wrap(clerr.ConfigInvalid, "write isolated home file", writeErr)
		if closeErr != nil {
			failure = errors.Join(failure, clerr.Wrap(clerr.CleanupFailed, "close isolated home file", closeErr))
		}
		return failure
	}
	if closeErr != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "close isolated home file", closeErr)
	}
	return nil
}

func closeFile(primary error, file *os.File) error {
	if err := file.Close(); err != nil {
		return errors.Join(primary, clerr.Wrap(clerr.CleanupFailed, "close isolated home file", err))
	}
	return primary
}

func closeRoot(primary error, root *os.Root, message string) error {
	if root == nil {
		return primary
	}
	if err := root.Close(); err != nil {
		return errors.Join(primary, clerr.Wrap(clerr.CleanupFailed, message, err))
	}
	return primary
}

func failPrepare(workspace *Workspace, primary error) error {
	if cleanupErr := workspace.cleanup(); cleanupErr != nil {
		return errors.Join(primary, cleanupErr)
	}
	return primary
}

func writeAll(file *os.File, value []byte) error {
	for len(value) > 0 {
		written, err := file.Write(value)
		if err != nil {
			return err
		}
		if written == 0 {
			return fs.ErrInvalid
		}
		value = value[written:]
	}
	return nil
}

func (w *Workspace) ApplyEnvironment(env map[string]string) {
	if w == nil || env == nil {
		return
	}
	if w.goos == "windows" {
		deleteEnvironmentKeysFold(env,
			"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "HOMEDRIVE", "HOMEPATH",
			"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
		)
	}
	env["HOME"] = w.home
	env["XDG_CONFIG_HOME"] = filepath.Join(w.home, ".config")
	env["XDG_DATA_HOME"] = filepath.Join(w.home, ".local", "share")
	env["XDG_CACHE_HOME"] = filepath.Join(w.home, ".cache")
	env["XDG_STATE_HOME"] = filepath.Join(w.home, ".local", "state")
	if w.goos != "windows" {
		return
	}
	env["USERPROFILE"] = w.home
	env["APPDATA"] = filepath.Join(w.home, "AppData", "Roaming")
	env["LOCALAPPDATA"] = filepath.Join(w.home, "AppData", "Local")
	volume := filepath.VolumeName(w.home)
	if volume != "" {
		env["HOMEDRIVE"] = volume
		env["HOMEPATH"] = strings.TrimPrefix(w.home, volume)
	}
}

func deleteEnvironmentKeysFold(env map[string]string, keys ...string) {
	for existing := range env {
		for _, key := range keys {
			if strings.EqualFold(existing, key) {
				delete(env, existing)
				break
			}
		}
	}
}

func (w *Workspace) HomeDir() string {
	if w == nil {
		return ""
	}
	return w.home
}

func (w *Workspace) Close() error {
	if w == nil {
		return nil
	}
	w.closeOnce.Do(func() {
		w.closeErr = w.cleanup()
	})
	return w.closeErr
}

func (w *Workspace) cleanup() error {
	var lockErr error
	if w.lock != nil {
		lockErr = w.lock.Close()
		w.lock = nil
	}
	var removeErr error
	if w.root != "" {
		if err := os.RemoveAll(w.root); err != nil {
			removeErr = clerr.Wrap(clerr.CleanupFailed, "remove isolated home workspace", err)
		}
		w.root = ""
	}
	return errors.Join(lockErr, removeErr)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
