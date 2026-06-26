package reset

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
)

const (
	sqliteFilename      = "envvault.sqlite"
	talosSQLiteFilename = "talos.sqlite"
	jwksFilename        = "envvault-jwks.json"
	auditFilename       = "audit.jsonl"
	signingKeyID        = "current"
)

type Options struct {
	DryRun bool
}

type Result struct {
	Files       []string
	KeyringKeys []string
}

type Planner struct {
	Paths   config.Paths
	Secrets keyring.Store
}

func (p Planner) Reset(ctx context.Context, options Options) (Result, error) {
	result, err := p.plan()
	if err != nil {
		return Result{}, err
	}
	if options.DryRun {
		return result, nil
	}

	for _, key := range result.KeyringKeys {
		if p.Secrets == nil {
			return Result{}, clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable")
		}
		if err := p.Secrets.Delete(ctx, keyring.Key(key)); err != nil {
			return Result{}, err
		}
	}
	for _, path := range result.Files {
		if err := removePath(path); err != nil {
			return Result{}, err
		}
	}
	return result, nil
}

func (p Planner) plan() (Result, error) {
	cfg, err := config.Load(p.Paths.ConfigFile)
	if err != nil && !configMissing(err) {
		return Result{}, err
	}

	files := []string{
		p.Paths.ConfigFile,
		filepath.Join(p.Paths.DataDir, sqliteFilename),
		filepath.Join(p.Paths.DataDir, talosSQLiteFilename),
		filepath.Join(p.Paths.DataDir, jwksFilename),
		filepath.Join(p.Paths.DataDir, auditFilename),
		p.Paths.CacheDir,
	}
	keys := []string{
		string(keyring.TalosHMACKey()),
		string(keyring.TalosSigningKey(signingKeyID)),
	}
	for name, stored := range cfg.Profiles {
		if stored.Kind == profile.KindProviderProxy {
			keys = append(keys, string(keyring.ProviderAPIKey(name)))
			continue
		}
		keys = append(keys, string(keyring.ProfileParentKey(name)))
	}
	sort.Strings(files)
	sort.Strings(keys)
	return Result{Files: files, KeyringKeys: keys}, nil
}

func configMissing(err error) bool {
	var envvaultErr *clerr.Error
	if !errors.As(err, &envvaultErr) || envvaultErr.Err == nil {
		return false
	}
	return errors.Is(envvaultErr.Err, os.ErrNotExist)
}

func removePath(path string) error {
	if path == "" {
		return nil
	}
	if err := os.RemoveAll(path); err != nil {
		return clerr.Wrap(clerr.CleanupFailed, "remove envvault path", err)
	}
	return nil
}
