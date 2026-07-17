package homefile

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/keyring"
)

const (
	maxTemplateBytes = 4 << 20
	maxTemplateDepth = 128
)

type contentResolver struct {
	secrets keyring.Store
	cache   map[string][]byte
}

func newContentResolver(secrets keyring.Store) *contentResolver {
	return &contentResolver{
		secrets: secrets,
		cache:   map[string][]byte{},
	}
}

func (r *contentResolver) Materialize(ctx context.Context, sourceDir string, spec Spec) ([]byte, error) {
	switch spec.Kind {
	case KindCredential:
		secret, err := r.credential(ctx, spec.Reference.Profile)
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), secret...), nil
	case KindTemplate:
		return r.renderTemplate(ctx, sourceDir, spec)
	default:
		return nil, clerr.New(clerr.ConfigInvalid, "unknown --home-file source kind")
	}
}

func (r *contentResolver) renderTemplate(ctx context.Context, sourceDir string, spec Spec) ([]byte, error) {
	body, err := readTemplateSource(sourceDir, spec.Source)
	if err != nil {
		return nil, err
	}
	defer zero(body)
	if !utf8.Valid(body) {
		return nil, clerr.New(clerr.ConfigInvalid, "home file template is not valid UTF-8")
	}

	switch spec.Format {
	case FormatJSON:
		return r.renderJSON(ctx, body)
	case FormatYAML:
		return r.renderYAML(ctx, body)
	case FormatTOML:
		return r.renderTOML(ctx, body)
	default:
		return nil, clerr.New(clerr.ConfigInvalid, "unknown --home-file template format")
	}
}

func readTemplateSource(sourceDir, source string) ([]byte, error) {
	absolute := source
	if !filepath.IsAbs(source) {
		if sourceDir == "" || !filepath.IsAbs(sourceDir) {
			return nil, clerr.New(clerr.ConfigInvalid, "absolute source directory is required for relative --home-file templates")
		}
		absolute = filepath.Join(sourceDir, source)
	}
	absolute = filepath.Clean(absolute)
	rootPath := filepath.Dir(absolute)
	relative := filepath.Base(absolute)
	if rootPath == "" || !filepath.IsAbs(rootPath) || relative == "." {
		return nil, clerr.New(clerr.ConfigInvalid, "absolute source directory is required for relative --home-file templates")
	}
	root, err := os.OpenRoot(filepath.Clean(rootPath))
	if err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "open home file template source directory", err)
	}
	body, readErr := readTemplateFile(root, relative)
	closeErr := root.Close()
	if readErr != nil {
		if closeErr != nil {
			return nil, errors.Join(readErr, clerr.Wrap(clerr.CleanupFailed, "close home file template source directory", closeErr))
		}
		return nil, readErr
	}
	if closeErr != nil {
		zero(body)
		return nil, clerr.Wrap(clerr.CleanupFailed, "close home file template source directory", closeErr)
	}
	return body, nil
}

func readTemplateFile(root *os.Root, source string) ([]byte, error) {
	localized, err := filepath.Localize(filepath.ToSlash(source))
	if err != nil {
		return nil, invalidTemplateSource()
	}
	info, err := root.Lstat(localized)
	if err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "inspect home file template", err)
	}
	if !info.Mode().IsRegular() {
		return nil, clerr.New(clerr.ConfigInvalid, "home file template must be a regular file without symlinks")
	}
	file, err := root.OpenFile(localized, sourceOpenFlags(), 0)
	if err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "open home file template", err)
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return nil, clerr.Wrap(clerr.ConfigInvalid, "inspect home file template", statErr)
	}
	if !openedInfo.Mode().IsRegular() {
		_ = file.Close()
		return nil, clerr.New(clerr.ConfigInvalid, "home file template must be a regular file")
	}
	if !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return nil, clerr.New(clerr.ConfigInvalid, "home file template changed while it was being opened")
	}
	body, readErr := io.ReadAll(io.LimitReader(file, maxTemplateBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		zero(body)
		return nil, clerr.Wrap(clerr.ConfigInvalid, "read home file template", readErr)
	}
	if closeErr != nil {
		zero(body)
		return nil, clerr.Wrap(clerr.CleanupFailed, "close home file template", closeErr)
	}
	if len(body) > maxTemplateBytes {
		zero(body)
		return nil, clerr.New(clerr.ConfigInvalid, "home file template exceeds 4 MiB")
	}
	return body, nil
}

func (r *contentResolver) Resolve(ctx context.Context, value any) (any, error) {
	return r.resolveValue(ctx, value, 0)
}

func (r *contentResolver) resolveValue(ctx context.Context, value any, depth int) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if depth > maxTemplateDepth {
		return nil, clerr.New(clerr.ConfigInvalid, "home file template nesting exceeds 128 levels")
	}
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			resolved, err := r.resolveValue(ctx, typed[key], depth+1)
			if err != nil {
				return nil, err
			}
			typed[key] = resolved
		}
		return typed, nil
	case []any:
		for index := range typed {
			resolved, err := r.resolveValue(ctx, typed[index], depth+1)
			if err != nil {
				return nil, err
			}
			typed[index] = resolved
		}
		return typed, nil
	case string:
		return r.resolveString(ctx, typed)
	default:
		return value, nil
	}
}

func (r *contentResolver) resolveString(ctx context.Context, value string) (string, error) {
	reference, isReference, err := envref.ParseValue(value)
	if err != nil {
		return "", err
	}
	if !isReference {
		if strings.Contains(value, "envvault://") {
			return "", clerr.New(clerr.ConfigInvalid, "EnvVault reference must be the complete template string value")
		}
		return value, nil
	}
	if reference.Part != envref.PartDefault {
		return "", clerr.New(clerr.ConfigInvalid, "home file template supports direct credential references only")
	}
	secret, err := r.credential(ctx, reference.Profile)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(secret) {
		return "", clerr.New(clerr.ConfigInvalid, "credential value is not valid UTF-8 for a template string")
	}
	return string(secret), nil
}

func (r *contentResolver) credential(ctx context.Context, name string) ([]byte, error) {
	if secret, ok := r.cache[name]; ok {
		return secret, nil
	}
	secret, err := r.secrets.Get(ctx, keyring.CredentialValue(name))
	if err != nil {
		return nil, err
	}
	r.cache[name] = secret
	return secret, nil
}

func (r *contentResolver) Close() {
	for name, secret := range r.cache {
		zero(secret)
		delete(r.cache, name)
	}
}

func copyWithTrailingNewline(rendered []byte) []byte {
	if len(rendered) > 0 && rendered[len(rendered)-1] == '\n' {
		output := append([]byte(nil), rendered...)
		zero(rendered)
		return output
	}
	output := make([]byte, len(rendered)+1)
	copy(output, rendered)
	output[len(rendered)] = '\n'
	zero(rendered)
	return output
}
