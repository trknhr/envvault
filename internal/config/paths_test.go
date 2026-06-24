package config_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/trknhr/credlease/internal/config"
)

func TestPathsForLinuxUseXDGDirectories(t *testing.T) {
	paths, err := config.PathsFor(config.PathEnv{
		Home:          "/home/alice",
		XDGConfigHome: "/xdg/config",
		XDGDataHome:   "/xdg/data",
		XDGCacheHome:  "/xdg/cache",
	}, "linux")
	if err != nil {
		t.Fatalf("PathsFor() error = %v", err)
	}

	if paths.ConfigDir != "/xdg/config/credlease" {
		t.Fatalf("ConfigDir = %q", paths.ConfigDir)
	}
	if paths.ConfigFile != "/xdg/config/credlease/config.yaml" {
		t.Fatalf("ConfigFile = %q", paths.ConfigFile)
	}
	if paths.DataDir != "/xdg/data/credlease" {
		t.Fatalf("DataDir = %q", paths.DataDir)
	}
	if paths.CacheDir != "/xdg/cache/credlease" {
		t.Fatalf("CacheDir = %q", paths.CacheDir)
	}
}

func TestPathsForLinuxFallsBackToHome(t *testing.T) {
	paths, err := config.PathsFor(config.PathEnv{Home: "/home/alice"}, "linux")
	if err != nil {
		t.Fatalf("PathsFor() error = %v", err)
	}

	if paths.ConfigDir != "/home/alice/.config/credlease" {
		t.Fatalf("ConfigDir = %q", paths.ConfigDir)
	}
	if paths.DataDir != "/home/alice/.local/share/credlease" {
		t.Fatalf("DataDir = %q", paths.DataDir)
	}
	if paths.CacheDir != "/home/alice/.cache/credlease" {
		t.Fatalf("CacheDir = %q", paths.CacheDir)
	}
}

func TestEnsureCreatesPrivateDirectories(t *testing.T) {
	root := t.TempDir()
	paths := config.Paths{
		ConfigDir:  filepath.Join(root, "config"),
		ConfigFile: filepath.Join(root, "config", "config.yaml"),
		DataDir:    filepath.Join(root, "data"),
		CacheDir:   filepath.Join(root, "cache"),
	}

	if err := paths.Ensure(); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}

	for _, dir := range []string{paths.ConfigDir, paths.DataDir, paths.CacheDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("Stat(%s) error = %v", dir, err)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", dir)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
			t.Fatalf("%s mode = %v, want 0700", dir, info.Mode().Perm())
		}
	}
}
