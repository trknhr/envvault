package process_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/process"
)

func TestRunnerInjectsEnvironmentAndCapturesOutput(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	runner := process.Runner{}

	code, err := runner.Run(context.Background(), process.RunInput{
		Command: helperCommand("env"),
		Env: map[string]string{
			"CREDLEASE_HELPER_PROCESS": "1",
			"TOKEN":                    "leased-jwt",
			"PLAIN":                    "value",
			"REMOVE":                   "",
		},
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "TOKEN=leased-jwt\n") {
		t.Fatalf("stdout = %q, want TOKEN", stdout.String())
	}
	if !strings.Contains(stdout.String(), "PLAIN=value\n") {
		t.Fatalf("stdout = %q, want PLAIN", stdout.String())
	}
}

func TestRunnerPropagatesExitCode(t *testing.T) {
	runner := process.Runner{}

	code, err := runner.Run(context.Background(), process.RunInput{
		Command: helperCommand("exit-42"),
		Env:     map[string]string{"CREDLEASE_HELPER_PROCESS": "1"},
		Stdout:  new(bytes.Buffer),
		Stderr:  new(bytes.Buffer),
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if code != 42 {
		t.Fatalf("exit code = %d, want 42", code)
	}
}

func TestRunnerRejectsMissingCommand(t *testing.T) {
	runner := process.Runner{}

	_, err := runner.Run(context.Background(), process.RunInput{})
	if err == nil {
		t.Fatal("Run() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ConfigInvalid {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ConfigInvalid)
	}
}

func TestEnvironReturnsDeterministicAssignments(t *testing.T) {
	got := process.Environ(map[string]string{
		"B": "2",
		"A": "1",
	})

	want := []string{"A=1", "B=2"}
	if len(got) != len(want) {
		t.Fatalf("len(Environ()) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Environ()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRunnerForwardsSignals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Interrupt forwarding is platform-specific on Windows")
	}

	signals := make(chan os.Signal, 1)
	var stdout lockedBuffer
	var stderr lockedBuffer
	runner := process.Runner{}
	done := make(chan struct {
		code int
		err  error
	}, 1)

	go func() {
		code, err := runner.Run(context.Background(), process.RunInput{
			Command: helperCommand("wait-signal"),
			Env:     map[string]string{"CREDLEASE_HELPER_PROCESS": "1"},
			Signals: signals,
			Stdout:  &stdout,
			Stderr:  &stderr,
		})
		done <- struct {
			code int
			err  error
		}{code: code, err: err}
	}()

	waitForOutput(t, &stdout, "ready\n")
	signals <- os.Interrupt

	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("Run() error = %v; stderr=%q", result.err, stderr.String())
		}
		if result.code != 77 {
			t.Fatalf("exit code = %d, want 77; stdout=%q stderr=%q", result.code, stdout.String(), stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("runner did not finish after signal; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("CREDLEASE_HELPER_PROCESS") != "1" {
		return
	}
	args := os.Args
	idx := -1
	for i, arg := range args {
		if arg == "--" {
			idx = i
			break
		}
	}
	if idx == -1 || idx+1 >= len(args) {
		fmt.Fprintln(os.Stderr, "missing helper mode")
		os.Exit(2)
	}

	switch args[idx+1] {
	case "env":
		fmt.Printf("TOKEN=%s\n", os.Getenv("TOKEN"))
		fmt.Printf("PLAIN=%s\n", os.Getenv("PLAIN"))
		fmt.Printf("REMOVE=%s\n", os.Getenv("REMOVE"))
		os.Exit(0)
	case "exit-42":
		os.Exit(42)
	case "wait-signal":
		signalCh := make(chan os.Signal, 1)
		process.NotifyInterrupt(signalCh)
		fmt.Println("ready")
		<-signalCh
		os.Exit(77)
	default:
		fmt.Fprintf(os.Stderr, "unknown helper mode %q\n", args[idx+1])
		os.Exit(2)
	}
}

func helperCommand(mode string) []string {
	return []string{os.Args[0], "-test.run=TestHelperProcess", "--", mode}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func waitForOutput(t *testing.T, buf interface{ String() string }, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in stdout %q", want, buf.String())
}
