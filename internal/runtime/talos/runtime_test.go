package talos_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/trknhr/credlease/internal/clerr"
	runtimetalos "github.com/trknhr/credlease/internal/runtime/talos"
)

func TestRuntimeStartsOnLoopbackRandomPortAndStopsCleanly(t *testing.T) {
	runtime := runtimetalos.NewRuntime(runtimetalos.RuntimeOptions{
		BinaryPath:    os.Args[0],
		Args:          []string{"-test.run=TestTalosRuntimeHelperProcess", "--", "serve", "{address}"},
		HealthPath:    "/healthz",
		StartTimeout:  5 * time.Second,
		StopTimeout:   5 * time.Second,
		PollInterval:  10 * time.Millisecond,
		ExtraEnv:      []string{"CREDLEASE_TALOS_RUNTIME_HELPER=1"},
		StopSignal:    os.Interrupt,
		DialTimeout:   50 * time.Millisecond,
		PortCloseWait: time.Second,
	})

	endpoint, err := runtime.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if !strings.HasPrefix(endpoint.Address, "127.0.0.1:") {
		t.Fatalf("Address = %q, want loopback", endpoint.Address)
	}
	if endpoint.URL != "http://"+endpoint.Address {
		t.Fatalf("URL = %q, want http://%s", endpoint.URL, endpoint.Address)
	}

	resp, err := http.Get(endpoint.URL + "/healthz")
	if err != nil {
		t.Fatalf("health GET error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", resp.StatusCode)
	}

	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if portAccepts(endpoint.Address) {
		t.Fatalf("runtime port %s still accepts connections after Stop", endpoint.Address)
	}
	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop() error = %v", err)
	}
}

func TestRuntimeStartsOnConfiguredLoopbackAddress(t *testing.T) {
	address := reserveTestAddress(t)
	runtime := runtimetalos.NewRuntime(runtimetalos.RuntimeOptions{
		BinaryPath:    os.Args[0],
		Address:       address,
		Args:          []string{"-test.run=TestTalosRuntimeHelperProcess", "--", "serve", "{address}"},
		HealthPath:    "/healthz",
		StartTimeout:  5 * time.Second,
		StopTimeout:   5 * time.Second,
		PollInterval:  10 * time.Millisecond,
		ExtraEnv:      []string{"CREDLEASE_TALOS_RUNTIME_HELPER=1"},
		StopSignal:    os.Interrupt,
		DialTimeout:   50 * time.Millisecond,
		PortCloseWait: time.Second,
	})

	endpoint, err := runtime.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer runtime.Stop(context.Background())
	if endpoint.Address != address {
		t.Fatalf("Address = %q, want configured %q", endpoint.Address, address)
	}
	if endpoint.URL != "http://"+address {
		t.Fatalf("URL = %q, want http://%s", endpoint.URL, address)
	}
}

func TestRuntimeStartFailureKillsProcessAndRedactsOutput(t *testing.T) {
	runtime := runtimetalos.NewRuntime(runtimetalos.RuntimeOptions{
		BinaryPath:    os.Args[0],
		Args:          []string{"-test.run=TestTalosRuntimeHelperProcess", "--", "leak-and-sleep", "{address}"},
		HealthPath:    "/healthz",
		StartTimeout:  50 * time.Millisecond,
		StopTimeout:   5 * time.Second,
		PollInterval:  5 * time.Millisecond,
		ExtraEnv:      []string{"CREDLEASE_TALOS_RUNTIME_HELPER=1"},
		StopSignal:    os.Interrupt,
		DialTimeout:   10 * time.Millisecond,
		PortCloseWait: time.Second,
	})

	_, err := runtime.Start(context.Background())
	if err == nil {
		t.Fatal("Start() error = nil, want timeout")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.RuntimeUnavailable {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.RuntimeUnavailable)
	}
	if strings.Contains(err.Error(), "parent-secret") || strings.Contains(err.Error(), "bootstrap-jwt") {
		t.Fatalf("error leaked helper output: %q", err.Error())
	}
}

func TestRuntimeInvokesProcessLifecycleCallbacks(t *testing.T) {
	started := make(chan int, 1)
	stopped := make(chan int, 1)
	runtime := runtimetalos.NewRuntime(runtimetalos.RuntimeOptions{
		BinaryPath:    os.Args[0],
		Args:          []string{"-test.run=TestTalosRuntimeHelperProcess", "--", "serve", "{address}"},
		HealthPath:    "/healthz",
		StartTimeout:  5 * time.Second,
		StopTimeout:   5 * time.Second,
		PollInterval:  10 * time.Millisecond,
		ExtraEnv:      []string{"CREDLEASE_TALOS_RUNTIME_HELPER=1"},
		StopSignal:    os.Interrupt,
		DialTimeout:   50 * time.Millisecond,
		PortCloseWait: time.Second,
		ProcessStarted: func(pid int) error {
			started <- pid
			return nil
		},
		ProcessStopped: func(pid int) error {
			stopped <- pid
			return nil
		},
	})

	if _, err := runtime.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	var pid int
	select {
	case pid = <-started:
		if pid <= 0 {
			t.Fatalf("started pid = %d, want positive pid", pid)
		}
	case <-time.After(time.Second):
		t.Fatal("ProcessStarted was not called")
	}

	if err := runtime.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	select {
	case got := <-stopped:
		if got != pid {
			t.Fatalf("stopped pid = %d, want %d", got, pid)
		}
	case <-time.After(time.Second):
		t.Fatal("ProcessStopped was not called")
	}
}

func TestRuntimeVersionRunsConfiguredVersionCommand(t *testing.T) {
	runtime := runtimetalos.NewRuntime(runtimetalos.RuntimeOptions{
		BinaryPath:  os.Args[0],
		VersionArgs: []string{"-test.run=TestTalosRuntimeHelperProcess", "--", "version", "unused"},
		ExtraEnv:    []string{"CREDLEASE_TALOS_RUNTIME_HELPER=1"},
	})

	version, err := runtime.Version(context.Background())
	if err != nil {
		t.Fatalf("Version() error = %v", err)
	}
	if version != "talos-test v0.1.0" {
		t.Fatalf("Version() = %q", version)
	}
}

func TestRuntimeMigrateRunsConfiguredMigrationCommand(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "migrated")
	runtime := runtimetalos.NewRuntime(runtimetalos.RuntimeOptions{
		BinaryPath:  os.Args[0],
		MigrateArgs: []string{"-test.run=TestTalosRuntimeHelperProcess", "--", "migrate", "unused"},
		ExtraEnv: []string{
			"CREDLEASE_TALOS_RUNTIME_HELPER=1",
			"CREDLEASE_MIGRATION_MARKER=" + marker,
		},
	})

	if err := runtime.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("migration marker missing: %v", err)
	}
}

func TestTalosRuntimeHelperProcess(t *testing.T) {
	if os.Getenv("CREDLEASE_TALOS_RUNTIME_HELPER") != "1" {
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
	if idx == -1 || idx+2 >= len(args) {
		fmt.Fprintln(os.Stderr, "missing helper mode/address")
		os.Exit(2)
	}

	switch args[idx+1] {
	case "serve":
		serveRuntimeHelper(args[idx+2])
	case "leak-and-sleep":
		fmt.Fprintln(os.Stderr, "parent-secret bootstrap-jwt")
		time.Sleep(5 * time.Second)
		os.Exit(0)
	case "version":
		fmt.Println("talos-test v0.1.0")
		os.Exit(0)
	case "migrate":
		if err := os.WriteFile(os.Getenv("CREDLEASE_MIGRATION_MARKER"), []byte("ok"), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "write marker failed: %v\n", err)
			os.Exit(2)
		}
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown helper mode %q\n", args[idx+1])
		os.Exit(2)
	}
}

func serveRuntimeHelper(address string) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen failed: %v\n", err)
		os.Exit(2)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		http.NotFound(w, r)
	})}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		_ = server.Close()
	}()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "serve failed: %v\n", err)
		os.Exit(2)
	}
	os.Exit(0)
}

func portAccepts(address string) bool {
	conn, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func reserveTestAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()
	return listener.Addr().String()
}
