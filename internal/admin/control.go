package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/config"
)

const (
	stateFilename  = "admin-state.json"
	tokenEnvName   = "ENVVAULT_ADMIN_TOKEN"
	startTimeout   = 5 * time.Second
	stopTimeout    = 5 * time.Second
	pollInterval   = 100 * time.Millisecond
	adminLogFile   = "admin.log"
	defaultMode600 = 0o600
)

type Control struct {
	Paths         config.Paths
	Executable    string
	TokenSource   func() (string, error)
	StartProcess  func(context.Context, ProcessRequest) (Process, error)
	SignalProcess func(pid int, signal os.Signal) error
	WaitReady     func(context.Context, string) error
	CheckReady    func(context.Context, string) error
	WaitStopped   func(context.Context, string) error
	Now           func() time.Time
}

type StartRequest struct {
	Addr string
}

type State struct {
	PID       int       `json:"pid"`
	Addr      string    `json:"addr"`
	Token     string    `json:"token"`
	URL       string    `json:"url"`
	StartedAt time.Time `json:"started_at"`
}

type Status struct {
	Running bool
	State   State
}

type ProcessRequest struct {
	Executable string
	Args       []string
	Env        []string
	LogPath    string
}

type Process struct {
	PID int
}

func (c Control) Start(ctx context.Context, request StartRequest) (State, error) {
	if existing, err := c.Status(ctx); err == nil && existing.Running {
		return existing.State, nil
	}
	addr := request.Addr
	if strings.TrimSpace(addr) == "" {
		addr = DefaultAddr
	}
	if isRandomPort(addr) {
		return State{}, clerr.New(clerr.ConfigInvalid, "admin start requires a fixed port")
	}
	tokenSource := c.TokenSource
	if tokenSource == nil {
		tokenSource = NewToken
	}
	token, err := tokenSource()
	if err != nil {
		return State{}, err
	}
	if strings.TrimSpace(token) == "" {
		return State{}, clerr.New(clerr.ConfigInvalid, "admin token is required")
	}
	executable := c.Executable
	if strings.TrimSpace(executable) == "" {
		executable, err = os.Executable()
		if err != nil {
			return State{}, clerr.Wrap(clerr.ConfigInvalid, "locate envvault executable", err)
		}
	}
	if err := c.Paths.Ensure(); err != nil {
		return State{}, err
	}
	process, err := c.startProcess(ctx, ProcessRequest{
		Executable: executable,
		Args:       []string{"admin", "serve", "--addr", addr, "--token-env", tokenEnvName},
		Env:        append(os.Environ(), tokenEnvName+"="+token),
		LogPath:    filepath.Join(c.Paths.CacheDir, adminLogFile),
	})
	if err != nil {
		return State{}, err
	}
	state := State{
		PID:       process.PID,
		Addr:      addr,
		Token:     token,
		URL:       OpenURL(addr, token),
		StartedAt: c.now().UTC(),
	}
	waitReady := c.WaitReady
	if waitReady == nil {
		waitReady = waitHTTPReady
	}
	readyCtx, cancel := context.WithTimeout(ctx, startTimeout)
	defer cancel()
	if err := waitReady(readyCtx, state.URL); err != nil {
		_ = c.signalProcess(process.PID, os.Interrupt)
		return State{}, err
	}
	if err := WriteState(c.Paths, state); err != nil {
		_ = c.signalProcess(process.PID, os.Interrupt)
		return State{}, err
	}
	return state, nil
}

func (c Control) Status(ctx context.Context) (Status, error) {
	state, err := ReadState(c.Paths)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Status{}, nil
		}
		return Status{}, err
	}
	checkReady := c.CheckReady
	if checkReady == nil {
		checkReady = waitHTTPReady
	}
	checkCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := checkReady(checkCtx, state.URL); err != nil {
		return Status{Running: false, State: state}, nil
	}
	return Status{Running: true, State: state}, nil
}

func (c Control) Stop(ctx context.Context) (State, error) {
	state, err := ReadState(c.Paths)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, nil
		}
		return State{}, err
	}
	if state.PID > 0 {
		_ = c.signalProcess(state.PID, os.Interrupt)
	}
	waitStopped := c.WaitStopped
	if waitStopped == nil {
		waitStopped = waitHTTPStopped
	}
	stopCtx, cancel := context.WithTimeout(ctx, stopTimeout)
	defer cancel()
	if err := waitStopped(stopCtx, state.URL); err != nil && state.PID > 0 {
		_ = c.signalProcess(state.PID, os.Kill)
	}
	if err := os.Remove(statePath(c.Paths)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return State{}, clerr.Wrap(clerr.CleanupFailed, "remove admin state", err)
	}
	return state, nil
}

func (c Control) startProcess(ctx context.Context, request ProcessRequest) (Process, error) {
	if c.StartProcess != nil {
		return c.StartProcess(ctx, request)
	}
	return startBackgroundProcess(ctx, request)
}

func (c Control) signalProcess(pid int, signal os.Signal) error {
	if c.SignalProcess != nil {
		return c.SignalProcess(pid, signal)
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return clerr.Wrap(clerr.CleanupFailed, "find admin process", err)
	}
	return process.Signal(signal)
}

func (c Control) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func ReadState(paths config.Paths) (State, error) {
	raw, err := os.ReadFile(statePath(paths))
	if err != nil {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(raw, &state); err != nil {
		return State{}, clerr.Wrap(clerr.ConfigInvalid, "parse admin state", err)
	}
	if state.URL == "" || state.Addr == "" {
		return State{}, clerr.New(clerr.ConfigInvalid, "admin state is invalid")
	}
	return state, nil
}

func WriteState(paths config.Paths, state State) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "marshal admin state", err)
	}
	if err := os.MkdirAll(paths.CacheDir, 0o700); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "create admin state directory", err)
	}
	tmp, err := os.CreateTemp(paths.CacheDir, ".admin-state-*")
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "create admin state", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(defaultMode600); err != nil {
		_ = tmp.Close()
		return clerr.Wrap(clerr.ConfigInvalid, "secure admin state", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return clerr.Wrap(clerr.ConfigInvalid, "write admin state", err)
	}
	if _, err := tmp.Write([]byte("\n")); err != nil {
		_ = tmp.Close()
		return clerr.Wrap(clerr.ConfigInvalid, "write admin state newline", err)
	}
	if err := tmp.Close(); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "close admin state", err)
	}
	if err := os.Rename(tmpName, statePath(paths)); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "install admin state", err)
	}
	return os.Chmod(statePath(paths), defaultMode600)
}

func statePath(paths config.Paths) string {
	return filepath.Join(paths.CacheDir, stateFilename)
}

func startBackgroundProcess(ctx context.Context, request ProcessRequest) (Process, error) {
	if err := ctx.Err(); err != nil {
		return Process{}, err
	}
	logFile, err := os.OpenFile(request.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return Process{}, clerr.Wrap(clerr.ConfigInvalid, "open admin log", err)
	}
	defer logFile.Close()
	cmd := newBackgroundCommand(request.Executable, request.Args)
	cmd.Env = append([]string(nil), request.Env...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		return Process{}, clerr.Wrap(clerr.RuntimeUnavailable, "start admin server", err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Process.Release(); err != nil {
		return Process{}, clerr.Wrap(clerr.RuntimeUnavailable, "release admin process", err)
	}
	return Process{PID: pid}, nil
}

func waitHTTPReady(ctx context.Context, rawURL string) error {
	for {
		if err := ctx.Err(); err != nil {
			return clerr.Wrap(clerr.RuntimeUnavailable, "admin server did not become ready", err)
		}
		if adminAPIHealthy(ctx, rawURL) {
			return nil
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

func waitHTTPStopped(ctx context.Context, rawURL string) error {
	for {
		if err := ctx.Err(); err != nil {
			return clerr.Wrap(clerr.CleanupFailed, "admin server did not stop", err)
		}
		if !adminAPIHealthy(ctx, rawURL) {
			return nil
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

func adminAPIHealthy(ctx context.Context, rawURL string) bool {
	healthURL, token, err := adminHealthURL(rawURL)
	if err != nil {
		return false
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return false
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusOK
}

func adminHealthURL(rawURL string) (string, string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}
	token := parsed.Query().Get("token")
	if strings.TrimSpace(token) == "" {
		return "", "", errors.New("admin token missing")
	}
	parsed.Path = "/api/health"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), token, nil
}

func isRandomPort(addr string) bool {
	return strings.HasSuffix(strings.TrimSpace(addr), ":0")
}
