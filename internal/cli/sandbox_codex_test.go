package cli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/cli"
	"github.com/trknhr/envvault/internal/config"
)

func sandboxCodexApp(t *testing.T, options cli.Options) cli.App {
	t.Helper()
	options.Paths = config.Paths{DataDir: t.TempDir()}
	return cli.New(options)
}

func sandboxHelperFixture(t *testing.T, directory, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX helper fixture")
	}
	filename := filepath.Join(directory, "envvault-microsandbox")
	if err := os.WriteFile(filename, []byte("#!/bin/sh\nset -eu\n"+script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	return filename
}

func TestSandboxCodexUsesInvocationDirectoryAndPreservesArgumentsAndStdin(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "project with spaces")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	workspace, _ = filepath.EvalSymlinks(workspace)
	sandboxHelperFixture(t, t.TempDir(), "printf '%s\\n' \"$PWD\" \"$@\"\nIFS= read -r input\nprintf '%s\\n' \"$input\"\n")
	var out, stderr bytes.Buffer
	app := sandboxCodexApp(t, cli.Options{ProjectStartDir: workspace, Stdin: strings.NewReader("fixture input\n")})
	code := app.Run(context.Background(), []string{"sandbox", "codex", "--model", "test-model", "prompt with spaces"}, &out, &stderr)
	if code != 0 {
		t.Fatalf("launch failed: %s", &stderr)
	}
	want := strings.Join([]string{workspace, "codex", "--workspace", workspace, "--", "--model", "test-model", "prompt with spaces", "fixture input", ""}, "\n")
	if out.String() != want {
		t.Fatalf("workspace/argv/stdin were not preserved: %q", out.String())
	}
}

func TestSandboxCodexReturnsHelperExitCode(t *testing.T) {
	sandboxHelperFixture(t, t.TempDir(), "exit 23\n")
	app := sandboxCodexApp(t, cli.Options{ProjectStartDir: t.TempDir()})
	var out, stderr bytes.Buffer
	if code := app.Run(context.Background(), []string{"sandbox", "codex", "--", "--version"}, &out, &stderr); code != 23 {
		t.Fatalf("exit code = %d", code)
	}
}

func TestSandboxCodexForwardsResumeArgumentsWithoutSelectingStorage(t *testing.T) {
	sandboxHelperFixture(t, t.TempDir(), "printf '%s\\n' \"$@\"\n")
	workspace := t.TempDir()
	workspace, _ = filepath.EvalSymlinks(workspace)
	app := sandboxCodexApp(t, cli.Options{ProjectStartDir: workspace})
	for _, extra := range [][]string{{"resume"}, {"resume", "--last"}, {"resume", "0195b33c-0000-7000-8000-000000000001"}, {"--", "--workspace", "literal"}} {
		var out, stderr bytes.Buffer
		args := append([]string{"sandbox", "codex"}, extra...)
		if code := app.Run(context.Background(), args, &out, &stderr); code != 0 {
			t.Fatalf("forwarding failed: %s", &stderr)
		}
		forwarded := extra
		if len(forwarded) > 0 && forwarded[0] == "--" {
			forwarded = forwarded[1:]
		}
		want := strings.Join(append([]string{"codex", "--workspace", workspace, "--"}, forwarded...), "\n") + "\n"
		if out.String() != want {
			t.Fatalf("resume arguments changed: %q", out.String())
		}
	}
}

func TestSandboxCodexCancellationLetsHelperCleanUp(t *testing.T) {
	sandboxHelperFixture(t, t.TempDir(), `trap 'printf cleaned > "$ENVVAULT_TEST_MARKER_DIR/cleaned"; exit 0' INT TERM
printf ready > "$ENVVAULT_TEST_MARKER_DIR/ready"
while :; do /bin/sleep 0.05; done
`)
	markers := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app := sandboxCodexApp(t, cli.Options{ProjectStartDir: t.TempDir(), ParentEnv: append(os.Environ(), "ENVVAULT_TEST_MARKER_DIR="+markers), Stdin: strings.NewReader("")})
	done := make(chan int, 1)
	go func() { done <- app.Run(ctx, []string{"sandbox", "codex"}, new(bytes.Buffer), new(bytes.Buffer)) }()
	deadline := time.After(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(markers, "ready")); err == nil {
			break
		}
		select {
		case code := <-done:
			t.Fatalf("helper exited before ready: %d", code)
		case <-deadline:
			t.Fatal("helper did not start")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case code := <-done:
		if code != 130 {
			t.Fatalf("cancel exit code = %d", code)
		}
	case <-deadline:
		t.Fatal("helper did not finish cleanup")
	}
	if _, err := os.Stat(filepath.Join(markers, "cleaned")); err != nil {
		t.Fatal("helper was killed without cleanup")
	}
}

func TestSandboxCodexMissingHelperGivesInstallInstructions(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	var out, stderr bytes.Buffer
	app := sandboxCodexApp(t, cli.Options{ProjectStartDir: t.TempDir()})
	if code := app.Run(context.Background(), []string{"sandbox", "codex"}, &out, &stderr); code == 0 || !strings.Contains(stderr.String(), "envvault sandbox setup") {
		t.Fatal("missing helper did not give installation instructions")
	}
	if code := app.Run(context.Background(), []string{"sandbox", "codex", "--help"}, &out, &stderr); code != 0 || !strings.Contains(out.String(), "current directory") {
		t.Fatal("help required an installed helper")
	}
}

func TestSandboxCodexRejectsHelperInsideSharedWorkspaceIncludingSymlink(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		workspace := t.TempDir()
		helper := sandboxHelperFixture(t, workspace, "printf 'executed-untrusted-helper'\n")
		if symlink {
			bin := t.TempDir()
			if err := os.Symlink(helper, filepath.Join(bin, "envvault-microsandbox")); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin)
		}
		var out, stderr bytes.Buffer
		app := sandboxCodexApp(t, cli.Options{ProjectStartDir: workspace})
		if code := app.Run(context.Background(), []string{"sandbox", "codex"}, &out, &stderr); code == 0 || out.Len() != 0 || !strings.Contains(stderr.String(), "outside the shared workspace") {
			t.Fatal("executed a helper from the guest-writable workspace")
		}
	}
}
