package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/jwks"
	"github.com/trknhr/envvault/internal/keyring"
	runtimetalos "github.com/trknhr/envvault/internal/runtime/talos"
	"github.com/trknhr/envvault/internal/sqlite"
)

const (
	defaultTokenTTL       = 10 * time.Minute
	defaultMaxTokenTTL    = time.Hour
	defaultHMACBytes      = 32
	defaultSigningBytes   = 32
	defaultSigningKeyID   = "current"
	defaultSQLiteFilename = "envvault.sqlite"
	defaultJWKSFilename   = "envvault-jwks.json"
)

type RuntimeInstaller interface {
	Install(ctx context.Context, manifest runtimetalos.Manifest, platform runtimetalos.Platform) (runtimetalos.InstalledArtifact, error)
}

type SQLiteMigrator func(ctx context.Context, options sqlite.Options) error

type JWKSFetcher func(ctx context.Context) ([]byte, error)

type RuntimePrepareRequest struct {
	Paths          config.Paths
	Result         Result
	Installed      runtimetalos.InstalledArtifact
	InstallationID string
	HMACSecret     []byte
	SigningSeed    []byte
	SigningKeyID   string
}

type RuntimePreparer func(ctx context.Context, request RuntimePrepareRequest) (JWKSFetcher, error)

type Initializer struct {
	Paths             config.Paths
	Secrets           keyring.Store
	Installer         RuntimeInstaller
	SQLiteMigrate     SQLiteMigrator
	Manifest          runtimetalos.Manifest
	Platform          runtimetalos.Platform
	JWKS              JWKSFetcher
	PrepareRuntime    RuntimePreparer
	NewInstallationID func() (string, error)
	RandomBytes       func(n int) ([]byte, error)
	Now               func() time.Time
}

type Result struct {
	ConfigPath string
	SQLitePath string
	JWKSPath   string
}

func (i Initializer) Init(ctx context.Context) (Result, error) {
	result := i.result()
	if err := i.Paths.Ensure(); err != nil {
		return Result{}, err
	}

	if _, err := config.Load(i.Paths.ConfigFile); err == nil {
		return result, nil
	} else if !isConfigMissing(err) {
		return Result{}, err
	}

	if i.Secrets == nil {
		return Result{}, clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable")
	}
	if i.Installer == nil {
		return Result{}, clerr.New(clerr.RuntimeUnavailable, "talos installer is required")
	}
	migrate := i.SQLiteMigrate
	if migrate == nil {
		migrate = sqlite.Migrate
	}
	fetchJWKS := i.JWKS
	if fetchJWKS == nil && i.PrepareRuntime == nil {
		return Result{}, clerr.New(clerr.RuntimeUnavailable, "talos jwks fetcher is required")
	}

	installed, err := i.Installer.Install(ctx, i.Manifest, i.Platform)
	if err != nil {
		return Result{}, err
	}
	if err := migrate(ctx, sqlite.Options{Path: result.SQLitePath}); err != nil {
		return Result{}, err
	}

	installationID, err := i.installationID()
	if err != nil {
		return Result{}, err
	}

	hmacSecret, err := i.randomBytes(defaultHMACBytes)
	if err != nil {
		return Result{}, err
	}
	defer zero(hmacSecret)
	signingSecret, err := i.randomBytes(defaultSigningBytes)
	if err != nil {
		return Result{}, err
	}
	defer zero(signingSecret)

	if err := i.Secrets.Put(ctx, keyring.TalosHMACKey(), hmacSecret); err != nil {
		return Result{}, err
	}
	hmacStored := true
	if err := i.Secrets.Put(ctx, keyring.TalosSigningKey(defaultSigningKeyID), signingSecret); err != nil {
		if hmacStored {
			_ = i.Secrets.Delete(ctx, keyring.TalosHMACKey())
		}
		return Result{}, err
	}
	signingStored := true
	rollbackSecrets := func() {
		if signingStored {
			_ = i.Secrets.Delete(ctx, keyring.TalosSigningKey(defaultSigningKeyID))
		}
		if hmacStored {
			_ = i.Secrets.Delete(ctx, keyring.TalosHMACKey())
		}
	}

	if i.PrepareRuntime != nil {
		fetchJWKS, err = i.PrepareRuntime(ctx, RuntimePrepareRequest{
			Paths:          i.Paths,
			Result:         result,
			Installed:      installed,
			InstallationID: installationID,
			HMACSecret:     hmacSecret,
			SigningSeed:    signingSecret,
			SigningKeyID:   defaultSigningKeyID,
		})
		if err != nil {
			rollbackSecrets()
			return Result{}, err
		}
		if fetchJWKS == nil {
			rollbackSecrets()
			return Result{}, clerr.New(clerr.RuntimeUnavailable, "talos jwks fetcher is required")
		}
	}

	publicJWKS, err := fetchJWKS(ctx)
	if err != nil {
		rollbackSecrets()
		return Result{}, err
	}
	if err := jwks.Export(result.JWKSPath, publicJWKS); err != nil {
		rollbackSecrets()
		return Result{}, err
	}

	cfg := config.File{
		Version: 1,
		Installation: config.Installation{
			ID: installationID,
		},
		Runtime: config.Runtime{
			Talos: config.TalosRuntime{
				Mode:      "managed",
				Version:   installed.Version,
				Lifecycle: "on-demand",
			},
		},
		Defaults: config.Defaults{
			TokenTTL:    config.Duration(defaultTokenTTL),
			MaxTokenTTL: config.Duration(defaultMaxTokenTTL),
		},
		Profiles: map[string]config.Profile{},
	}
	if err := config.Save(i.Paths.ConfigFile, cfg); err != nil {
		rollbackSecrets()
		return Result{}, err
	}
	return result, nil
}

func (i Initializer) result() Result {
	return Result{
		ConfigPath: i.Paths.ConfigFile,
		SQLitePath: filepath.Join(i.Paths.DataDir, defaultSQLiteFilename),
		JWKSPath:   filepath.Join(i.Paths.DataDir, defaultJWKSFilename),
	}
}

func (i Initializer) randomBytes(n int) ([]byte, error) {
	if i.RandomBytes != nil {
		return i.RandomBytes(n)
	}
	value := make([]byte, n)
	if _, err := rand.Read(value); err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "generate secret material", err)
	}
	return value, nil
}

func (i Initializer) installationID() (string, error) {
	if i.NewInstallationID != nil {
		return i.NewInstallationID()
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", clerr.Wrap(clerr.ConfigInvalid, "generate installation id", err)
	}
	return "hex:" + hex.EncodeToString(raw[:]), nil
}

func isConfigMissing(err error) bool {
	var envvaultErr *clerr.Error
	if !errors.As(err, &envvaultErr) || envvaultErr.Err == nil {
		return false
	}
	return errors.Is(envvaultErr.Err, os.ErrNotExist)
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
