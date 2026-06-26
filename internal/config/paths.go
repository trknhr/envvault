package config

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/trknhr/envvault/internal/clerr"
)

type PathEnv struct {
	Home          string
	XDGConfigHome string
	XDGDataHome   string
	XDGCacheHome  string
}

type Paths struct {
	ConfigDir  string
	ConfigFile string
	DataDir    string
	CacheDir   string
}

func DefaultPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, clerr.Wrap(clerr.ConfigInvalid, "locate home directory", err)
	}
	return PathsFor(PathEnv{
		Home:          home,
		XDGConfigHome: os.Getenv("XDG_CONFIG_HOME"),
		XDGDataHome:   os.Getenv("XDG_DATA_HOME"),
		XDGCacheHome:  os.Getenv("XDG_CACHE_HOME"),
	}, runtime.GOOS)
}

func PathsFor(env PathEnv, goos string) (Paths, error) {
	if env.Home == "" {
		return Paths{}, clerr.New(clerr.ConfigInvalid, "home directory is required")
	}

	configBase, dataBase, cacheBase := baseDirs(env, goos)
	configDir := filepath.Join(configBase, "envvault")
	return Paths{
		ConfigDir:  configDir,
		ConfigFile: filepath.Join(configDir, "config.yaml"),
		DataDir:    filepath.Join(dataBase, "envvault"),
		CacheDir:   filepath.Join(cacheBase, "envvault"),
	}, nil
}

func (p Paths) Ensure() error {
	for _, dir := range []string{p.ConfigDir, p.DataDir, p.CacheDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return clerr.Wrap(clerr.ConfigInvalid, "create envvault directory", err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return clerr.Wrap(clerr.ConfigInvalid, "set envvault directory permissions", err)
		}
	}
	return nil
}

func baseDirs(env PathEnv, goos string) (configBase, dataBase, cacheBase string) {
	switch goos {
	case "darwin":
		configBase = filepath.Join(env.Home, "Library", "Application Support")
		dataBase = filepath.Join(env.Home, "Library", "Application Support")
		cacheBase = filepath.Join(env.Home, "Library", "Caches")
	case "windows":
		configBase = filepath.Join(env.Home, "AppData", "Roaming")
		dataBase = filepath.Join(env.Home, "AppData", "Local")
		cacheBase = filepath.Join(env.Home, "AppData", "Local", "Cache")
	default:
		configBase = firstNonEmpty(env.XDGConfigHome, filepath.Join(env.Home, ".config"))
		dataBase = firstNonEmpty(env.XDGDataHome, filepath.Join(env.Home, ".local", "share"))
		cacheBase = firstNonEmpty(env.XDGCacheHome, filepath.Join(env.Home, ".cache"))
	}
	return configBase, dataBase, cacheBase
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
