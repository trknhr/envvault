package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/admin"
	"github.com/trknhr/envvault/internal/config"
)

func TestControlStartLaunchesBackgroundServeWithTokenEnvAndWritesState(t *testing.T) {
	paths := testPaths(t)
	starter := &fakeProcessStarter{pid: 12345}
	var readyURL string
	control := admin.Control{
		Paths:        paths,
		Executable:   "/opt/envvault/bin/envvault",
		TokenSource:  func() (string, error) { return "admin-token", nil },
		StartProcess: starter.Start,
		WaitReady: func(_ context.Context, rawURL string) error {
			readyURL = rawURL
			return nil
		},
		Now: func() time.Time {
			return time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
		},
	}

	state, err := control.Start(context.Background(), admin.StartRequest{})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if starter.request.Executable != "/opt/envvault/bin/envvault" {
		t.Fatalf("executable = %q", starter.request.Executable)
	}
	if strings.Join(starter.request.Args, " ") != "admin serve --addr 127.0.0.1:17890 --token-env ENVVAULT_ADMIN_TOKEN" {
		t.Fatalf("args = %#v", starter.request.Args)
	}
	if strings.Contains(strings.Join(starter.request.Args, " "), "admin-token") {
		t.Fatalf("args leaked admin token: %#v", starter.request.Args)
	}
	if !containsString(starter.request.Env, "ENVVAULT_ADMIN_TOKEN=admin-token") {
		t.Fatalf("env = %#v, want admin token env", starter.request.Env)
	}
	if state.PID != 12345 || state.Addr != "127.0.0.1:17890" {
		t.Fatalf("state = %#v", state)
	}
	if state.URL != "http://127.0.0.1:17890/?token=admin-token" {
		t.Fatalf("URL = %q", state.URL)
	}
	if readyURL != "http://127.0.0.1:17890/?token=admin-token" {
		t.Fatalf("ready URL = %q", readyURL)
	}

	stored, err := admin.ReadState(paths)
	if err != nil {
		t.Fatalf("ReadState() error = %v", err)
	}
	if stored.Token != "admin-token" || stored.PID != 12345 {
		t.Fatalf("stored state = %#v", stored)
	}
	if info, err := os.Stat(filepath.Join(paths.CacheDir, "admin-state.json")); err != nil {
		t.Fatalf("state stat error = %v", err)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestControlStatusAndStopUseStoredState(t *testing.T) {
	paths := testPaths(t)
	state := admin.State{
		PID:       12345,
		Addr:      "127.0.0.1:17890",
		Token:     "admin-token",
		URL:       "http://127.0.0.1:17890/?token=admin-token",
		StartedAt: time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC),
	}
	if err := admin.WriteState(paths, state); err != nil {
		t.Fatalf("WriteState() error = %v", err)
	}
	var checkedURL string
	var signaledPID int
	control := admin.Control{
		Paths: paths,
		CheckReady: func(_ context.Context, rawURL string) error {
			checkedURL = rawURL
			return nil
		},
		SignalProcess: func(pid int, signal os.Signal) error {
			signaledPID = pid
			return nil
		},
		WaitStopped: func(_ context.Context, rawURL string) error {
			return nil
		},
	}

	status, err := control.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if !status.Running || status.State.URL != state.URL {
		t.Fatalf("status = %#v", status)
	}
	if checkedURL != state.URL {
		t.Fatalf("checked URL = %q", checkedURL)
	}

	stopped, err := control.Stop(context.Background())
	if err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if stopped.PID != 12345 || signaledPID != 12345 {
		t.Fatalf("stopped=%#v signaledPID=%d", stopped, signaledPID)
	}
	if _, err := admin.ReadState(paths); err == nil {
		t.Fatal("state still exists after Stop")
	}
}

func TestControlStartRejectsRandomPortForBackgroundStart(t *testing.T) {
	paths := testPaths(t)
	control := admin.Control{
		Paths:       paths,
		Executable:  "/opt/envvault/bin/envvault",
		TokenSource: func() (string, error) { return "admin-token", nil },
		StartProcess: func(context.Context, admin.ProcessRequest) (admin.Process, error) {
			t.Fatal("process should not start for random port background admin")
			return admin.Process{}, nil
		},
	}

	_, err := control.Start(context.Background(), admin.StartRequest{Addr: "127.0.0.1:0"})
	if err == nil {
		t.Fatal("Start() error = nil, want random port rejection")
	}
}

type fakeProcessStarter struct {
	request admin.ProcessRequest
	pid     int
}

func (s *fakeProcessStarter) Start(_ context.Context, request admin.ProcessRequest) (admin.Process, error) {
	s.request = request
	return admin.Process{PID: s.pid}, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestControlStatusReturnsStoppedWithoutState(t *testing.T) {
	status, err := (admin.Control{Paths: config.Paths{CacheDir: t.TempDir()}}).Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.Running {
		t.Fatalf("status = %#v, want stopped", status)
	}
}

func TestControlStatusRequiresMatchingAdminToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/api/health" && r.Header.Get("Authorization") == "Bearer real-token" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	paths := testPaths(t)
	state := admin.State{
		PID:       12345,
		Addr:      "127.0.0.1:17890",
		Token:     "stale-token",
		URL:       server.URL + "/?token=stale-token",
		StartedAt: time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC),
	}
	if err := admin.WriteState(paths, state); err != nil {
		t.Fatalf("WriteState() error = %v", err)
	}

	status, err := (admin.Control{Paths: paths}).Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.Running {
		t.Fatalf("status = %#v, want stopped for mismatched token", status)
	}
}
