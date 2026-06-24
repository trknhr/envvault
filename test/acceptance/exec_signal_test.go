package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/credlease/internal/cli"
	"github.com/trknhr/credlease/internal/process"
)

func TestExecForwardsSIGINTToChild(t *testing.T) {
	repoRoot := findRepoRoot(t)
	waitSignal := buildFixture(t, repoRoot, "wait-signal")
	projectRoot := t.TempDir()
	readyPath := filepath.Join(t.TempDir(), "ready")
	capturePath := filepath.Join(t.TempDir(), "signal.json")
	parentEnv := append(os.Environ(),
		"CREDLEASE_WAIT_SIGNAL_READY="+readyPath,
		"CREDLEASE_WAIT_SIGNAL_CAPTURE="+capturePath,
	)
	app := cli.New(cli.Options{
		ParentEnv:       parentEnv,
		ProjectStartDir: projectRoot,
		Profiles:        fakeProfiles(),
		Issuer:          &fakeIssuer{token: "leased-jwt"},
		Runner:          process.Runner{},
	})
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)

	go func() {
		done <- app.Run(context.Background(), []string{"exec", "--", waitSignal}, &stdout, &stderr)
	}()
	waitForFile(t, readyPath, 10*time.Second)

	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess(self) error = %v", err)
	}
	if err := self.Signal(os.Interrupt); err != nil {
		t.Fatalf("Signal(self, interrupt) error = %v", err)
	}

	var code int
	select {
	case code = <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("credlease exec did not exit after SIGINT; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if code != 130 {
		t.Fatalf("Run() code = %d, want 130 after SIGINT; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var record waitSignalRecord
	readJSONFile(t, capturePath, &record)
	if record.Signal != "interrupt" {
		t.Fatalf("child signal = %q, want interrupt", record.Signal)
	}
	if record.PID == 0 {
		t.Fatalf("child PID was not captured: %#v", record)
	}
	if strings.Contains(stdout.String()+stderr.String(), "leased-jwt") {
		t.Fatalf("CLI output leaked token while handling signal; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

type waitSignalRecord struct {
	Signal string `json:"signal"`
	PID    int    `json:"pid"`
}

func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatalf("Stat(%s) error = %v", path, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

func readJSONFile(t *testing.T, path string, out any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("Unmarshal(%s) error = %v; body=%q", path, err, raw)
	}
}
