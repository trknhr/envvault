package talos

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
)

type Endpoint struct {
	Address string
	URL     string
}

type RuntimeOptions struct {
	BinaryPath     string
	Address        string
	Args           []string
	VersionArgs    []string
	MigrateArgs    []string
	HealthPath     string
	StartTimeout   time.Duration
	StopTimeout    time.Duration
	PollInterval   time.Duration
	ExtraEnv       []string
	StopSignal     os.Signal
	DialTimeout    time.Duration
	PortCloseWait  time.Duration
	HTTPClient     *http.Client
	ProcessStarted func(pid int) error
	ProcessStopped func(pid int) error
}

type Runtime struct {
	options  RuntimeOptions
	mu       sync.Mutex
	cmd      *exec.Cmd
	done     chan error
	endpoint Endpoint
}

func NewRuntime(options RuntimeOptions) *Runtime {
	return &Runtime{options: options}
}

func (r *Runtime) Start(ctx context.Context) (Endpoint, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil {
		return r.endpoint, nil
	}
	if r.options.BinaryPath == "" {
		return Endpoint{}, clerr.New(clerr.RuntimeUnavailable, "talos binary path is required")
	}

	address, err := r.loopbackAddress()
	if err != nil {
		return Endpoint{}, err
	}
	endpoint := Endpoint{Address: address, URL: "http://" + address}
	args := expandArgs(r.options.Args, endpoint)
	stderr := &boundedBuffer{limit: 4096}

	cmd := exec.CommandContext(ctx, r.options.BinaryPath, args...)
	cmd.Env = append(os.Environ(), r.options.ExtraEnv...)
	cmd.Stdout = io.Discard
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return Endpoint{}, clerr.Wrap(clerr.RuntimeUnavailable, "start talos runtime", err)
	}
	if r.options.ProcessStarted != nil {
		if err := r.options.ProcessStarted(cmd.Process.Pid); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return Endpoint{}, err
		}
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	r.cmd = cmd
	r.done = done
	r.endpoint = endpoint
	if err := r.waitHealthy(ctx, endpoint, done); err != nil {
		_ = r.stopLocked(context.Background())
		r.cmd = nil
		r.done = nil
		r.endpoint = Endpoint{}
		return Endpoint{}, err
	}
	return endpoint, nil
}

func (r *Runtime) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopLocked(ctx)
}

func (r *Runtime) Migrate(ctx context.Context) error {
	if r.options.BinaryPath == "" {
		return clerr.New(clerr.RuntimeUnavailable, "talos binary path is required")
	}
	if len(r.options.MigrateArgs) == 0 {
		return clerr.New(clerr.RuntimeUnavailable, "talos migrate command is not configured")
	}
	_, err := runOneShot(ctx, r.options.BinaryPath, r.options.MigrateArgs, r.options.ExtraEnv)
	return err
}

func (r *Runtime) Version(ctx context.Context) (string, error) {
	if r.options.BinaryPath == "" {
		return "", clerr.New(clerr.RuntimeUnavailable, "talos binary path is required")
	}
	args := r.options.VersionArgs
	if len(args) == 0 {
		args = []string{"--version"}
	}
	out, err := runOneShot(ctx, r.options.BinaryPath, args, r.options.ExtraEnv)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (r *Runtime) stopLocked(ctx context.Context) error {
	if r.cmd == nil {
		return nil
	}
	cmd := r.cmd
	done := r.done
	endpoint := r.endpoint
	pid := cmd.Process.Pid
	r.cmd = nil
	r.done = nil
	r.endpoint = Endpoint{}
	defer func() {
		if r.options.ProcessStopped != nil {
			_ = r.options.ProcessStopped(pid)
		}
	}()

	stopSignal := r.options.StopSignal
	if stopSignal == nil {
		stopSignal = os.Interrupt
	}
	_ = cmd.Process.Signal(stopSignal)

	stopTimeout := r.options.StopTimeout
	if stopTimeout <= 0 {
		stopTimeout = 5 * time.Second
	}
	timer := time.NewTimer(stopTimeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-done
		return ctx.Err()
	case <-timer.C:
		_ = cmd.Process.Kill()
		<-done
		return clerr.New(clerr.CleanupFailed, "talos runtime did not stop before timeout")
	case err := <-done:
		if err != nil && !exitAfterSignal(err) {
			return clerr.Wrap(clerr.RuntimeUnavailable, "talos runtime exited", err)
		}
	}

	if err := waitPortClosed(endpoint.Address, r.options); err != nil {
		return err
	}
	return nil
}

func runOneShot(ctx context.Context, binary string, args []string, extraEnv []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stderr = &boundedBuffer{limit: 4096}
	out, err := cmd.Output()
	if err != nil {
		return nil, clerr.Wrap(clerr.RuntimeUnavailable, "run talos runtime command", err)
	}
	return out, nil
}

func (r *Runtime) waitHealthy(ctx context.Context, endpoint Endpoint, done <-chan error) error {
	healthPath := r.options.HealthPath
	if healthPath == "" {
		healthPath = "/healthz"
	}
	startTimeout := r.options.StartTimeout
	if startTimeout <= 0 {
		startTimeout = 10 * time.Second
	}
	poll := r.options.PollInterval
	if poll <= 0 {
		poll = 50 * time.Millisecond
	}
	deadline := time.NewTimer(startTimeout)
	defer deadline.Stop()

	for {
		ok, err := healthOK(ctx, r.httpClient(), endpoint.URL+healthPath)
		if ok {
			return nil
		}
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}

		pollTimer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			pollTimer.Stop()
			return ctx.Err()
		case err := <-done:
			pollTimer.Stop()
			if err != nil {
				return clerr.Wrap(clerr.RuntimeUnavailable, "talos runtime exited before health check", err)
			}
			return clerr.New(clerr.RuntimeUnavailable, "talos runtime exited before health check")
		case <-deadline.C:
			pollTimer.Stop()
			return clerr.New(clerr.RuntimeUnavailable, "talos runtime health check timed out")
		case <-pollTimer.C:
		}
	}
}

func (r *Runtime) httpClient() *http.Client {
	if r.options.HTTPClient != nil {
		return r.options.HTTPClient
	}
	timeout := r.options.DialTimeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	return &http.Client{Timeout: timeout}
}

func reserveLoopbackAddress() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", clerr.Wrap(clerr.RuntimeUnavailable, "reserve loopback talos port", err)
	}
	defer listener.Close()
	return listener.Addr().String(), nil
}

func (r *Runtime) loopbackAddress() (string, error) {
	if r.options.Address == "" {
		return reserveLoopbackAddress()
	}
	host, port, err := net.SplitHostPort(r.options.Address)
	if err != nil {
		return "", clerr.Wrap(clerr.RuntimeUnavailable, "parse talos runtime address", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", clerr.New(clerr.RuntimeUnavailable, "talos runtime address must bind to loopback")
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return "", clerr.New(clerr.RuntimeUnavailable, "talos runtime address port is invalid")
	}
	return r.options.Address, nil
}

func expandArgs(args []string, endpoint Endpoint) []string {
	out := make([]string, len(args))
	for i, arg := range args {
		arg = strings.ReplaceAll(arg, "{address}", endpoint.Address)
		arg = strings.ReplaceAll(arg, "{url}", endpoint.URL)
		out[i] = arg
	}
	return out
}

func healthOK(ctx context.Context, client *http.Client, rawURL string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

func waitPortClosed(address string, options RuntimeOptions) error {
	wait := options.PortCloseWait
	if wait <= 0 {
		wait = time.Second
	}
	dialTimeout := options.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 100 * time.Millisecond
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, dialTimeout)
		if err != nil {
			return nil
		}
		_ = conn.Close()
		time.Sleep(20 * time.Millisecond)
	}
	return clerr.New(clerr.CleanupFailed, "talos runtime port remained open after shutdown")
}

func exitAfterSignal(err error) bool {
	if err == nil {
		return true
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		return false
	}
	return exitErr.ExitCode() < 0
}

type boundedBuffer struct {
	mu    sync.Mutex
	limit int
	buf   bytes.Buffer
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.limit <= 0 || b.buf.Len() < b.limit {
		remaining := b.limit - b.buf.Len()
		if b.limit <= 0 || remaining > len(p) {
			remaining = len(p)
		}
		_, _ = b.buf.Write(p[:remaining])
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return fmt.Sprintf("%d bytes captured", b.buf.Len())
}
