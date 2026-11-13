package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/trknhr/envvault/internal/cli"
	"github.com/trknhr/envvault/internal/config"
)

func TestSandboxSetupInstallsManagedHelperAndRejectsTampering(t *testing.T) {
	if runtime.GOOS == "darwin" && runtime.GOARCH != "arm64" {
		t.Skip("Microsandbox native helper requires Apple Silicon on macOS")
	}
	source := sandboxHelperFixture(t, t.TempDir(), "printf 'managed-helper\\n'\n")
	app := sandboxCodexApp(t, cli.Options{ProjectStartDir: t.TempDir()})
	var out, stderr bytes.Buffer
	if code := app.Run(context.Background(), []string{"sandbox", "setup", "--helper", source}, &out, &stderr); code != 0 {
		t.Fatalf("setup failed: %s", &stderr)
	}
	line := strings.Split(out.String(), "\n")[0]
	installed := strings.TrimPrefix(line, "Microsandbox helper ready: ")
	if installed == source || !filepath.IsAbs(installed) {
		t.Fatal("helper was not copied into managed storage")
	}
	sandboxHelperFixture(t, t.TempDir(), "printf 'untrusted-PATH-helper\\n'\n")
	out.Reset()
	if code := app.Run(context.Background(), []string{"sandbox", "codex", "--version"}, &out, &stderr); code != 0 || out.String() != "managed-helper\n" {
		t.Fatalf("managed helper did not take precedence: %s %s", &out, &stderr)
	}
	if err := os.WriteFile(installed, []byte("#!/bin/sh\nprintf tampered\n"), 0700); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := app.Run(context.Background(), []string{"sandbox", "codex"}, &out, &stderr); code == 0 || out.Len() != 0 || !strings.Contains(stderr.String(), "checksum mismatch") {
		t.Fatal("modified managed helper fell back to PATH or executed")
	}
}

func TestSandboxSetupRejectsDataDirectoryInsideWorkspaceBeforeWriting(t *testing.T) {
	source := sandboxHelperFixture(t, t.TempDir(), "exit 0\n")
	for _, alias := range []bool{false, true} {
		workspace := t.TempDir()
		base := workspace
		if alias {
			base = filepath.Join(t.TempDir(), "alias")
			if err := os.Symlink(workspace, base); err != nil {
				t.Fatal(err)
			}
		}
		dataDir := filepath.Join(base, "new", "data")
		app := cli.New(cli.Options{ProjectStartDir: workspace, Paths: config.Paths{DataDir: dataDir}})
		var out, stderr bytes.Buffer
		if code := app.Run(context.Background(), []string{"sandbox", "setup", "--helper", source}, &out, &stderr); code == 0 || !strings.Contains(stderr.String(), "outside the shared workspace") {
			t.Fatalf("sandbox-writable install location accepted: %s", &stderr)
		}
		if _, err := os.Stat(filepath.Join(workspace, "new")); !os.IsNotExist(err) {
			t.Fatal("rejected setup wrote files in the workspace")
		}
	}
}
