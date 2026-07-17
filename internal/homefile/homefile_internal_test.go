package homefile

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/keyring"
)

func TestWriteCannotFollowParentSymlinkOutsideHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires additional privileges on some Windows hosts")
	}
	home := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, "link")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	root, err := os.OpenRoot(home)
	if err != nil {
		t.Fatalf("OpenRoot() error = %v", err)
	}
	defer root.Close()
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(context.Background(), keyring.CredentialValue("app/config"), []byte("secret-canary")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	resolver := newContentResolver(secrets)
	defer resolver.Close()

	err = write(context.Background(), root, "", resolver, Spec{
		Path:      "link/credential",
		Reference: envref.Reference{Profile: "app/config"},
	})
	if err == nil {
		t.Fatal("write() error = nil")
	}
	if _, err := os.Stat(filepath.Join(outside, "credential")); !os.IsNotExist(err) {
		t.Fatalf("credential escaped isolated home: %v", err)
	}
}

func TestDestinationKeyFoldsCaseOnlyOnWindows(t *testing.T) {
	if got := destinationKey("Config/Auth", "windows"); got != "config/auth" {
		t.Fatalf("destinationKey(windows) = %q", got)
	}
	if got := destinationKey("Config/Auth", "linux"); got != "Config/Auth" {
		t.Fatalf("destinationKey(linux) = %q", got)
	}
}

func TestValidateSpecsRejectsWindowsCaseCollision(t *testing.T) {
	err := validateSpecs([]Spec{
		{Path: "Config/Auth", Reference: envref.Reference{Profile: "first"}},
		{Path: "config/auth", Reference: envref.Reference{Profile: "second"}},
	}, "windows")
	if err == nil {
		t.Fatal("validateSpecs() error = nil")
	}
}

func TestFailPrepareSurfacesCleanupFailure(t *testing.T) {
	workspace := &Workspace{root: string([]byte{0})}
	primary := clerr.New(clerr.ConfigInvalid, "materialize failed")
	err := failPrepare(workspace, primary)
	if err == nil {
		t.Fatal("failPrepare() error = nil")
	}
	if !strings.Contains(err.Error(), string(clerr.ConfigInvalid)) || !strings.Contains(err.Error(), string(clerr.CleanupFailed)) {
		t.Fatalf("failPrepare() error = %q, want primary and cleanup errors", err)
	}
	if code, ok := clerr.CodeOf(err); !ok || code != clerr.ConfigInvalid {
		t.Fatalf("CodeOf(error) = %q, %v; want %q, true", code, ok, clerr.ConfigInvalid)
	}
}
