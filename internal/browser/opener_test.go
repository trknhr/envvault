package browser_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/trknhr/envvault/internal/browser"
	"github.com/trknhr/envvault/internal/clerr"
)

func TestCommandOpenerUsesOSDefaultBrowser(t *testing.T) {
	tests := []struct {
		goos string
		want commandCall
	}{
		{
			goos: "darwin",
			want: commandCall{name: "open", args: []string{"https://admin.dev.example.com/auth/envvault/complete?code=opaque"}},
		},
		{
			goos: "linux",
			want: commandCall{name: "xdg-open", args: []string{"https://admin.dev.example.com/auth/envvault/complete?code=opaque"}},
		},
		{
			goos: "windows",
			want: commandCall{name: "rundll32", args: []string{"url.dll,FileProtocolHandler", "https://admin.dev.example.com/auth/envvault/complete?code=opaque"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			runner := &recordingCommandRunner{}
			opener := browser.CommandOpener{
				GOOS:   tt.goos,
				Runner: runner,
			}

			err := opener.Open(context.Background(), "https://admin.dev.example.com/auth/envvault/complete?code=opaque", "")
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			if len(runner.calls) != 1 {
				t.Fatalf("calls = %d, want 1", len(runner.calls))
			}
			assertCommandCall(t, runner.calls[0], tt.want)
		})
	}
}

func TestCommandOpenerUsesExplicitBrowser(t *testing.T) {
	tests := []struct {
		name    string
		goos    string
		browser string
		want    commandCall
	}{
		{
			name:    "mac chrome",
			goos:    "darwin",
			browser: "chrome",
			want: commandCall{
				name: "open",
				args: []string{"-a", "Google Chrome", "https://admin.dev.example.com/auth/envvault/complete?code=opaque"},
			},
		},
		{
			name:    "linux chrome",
			goos:    "linux",
			browser: "chrome",
			want: commandCall{
				name: "google-chrome",
				args: []string{"https://admin.dev.example.com/auth/envvault/complete?code=opaque"},
			},
		},
		{
			name:    "linux chromium",
			goos:    "linux",
			browser: "chromium",
			want: commandCall{
				name: "chromium-browser",
				args: []string{"https://admin.dev.example.com/auth/envvault/complete?code=opaque"},
			},
		},
		{
			name:    "windows chrome",
			goos:    "windows",
			browser: "chrome",
			want: commandCall{
				name: "cmd",
				args: []string{"/c", "start", "", "chrome", "https://admin.dev.example.com/auth/envvault/complete?code=opaque"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &recordingCommandRunner{}
			opener := browser.CommandOpener{
				GOOS:   tt.goos,
				Runner: runner,
			}

			err := opener.Open(context.Background(), "https://admin.dev.example.com/auth/envvault/complete?code=opaque", tt.browser)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			if len(runner.calls) != 1 {
				t.Fatalf("calls = %d, want 1", len(runner.calls))
			}
			assertCommandCall(t, runner.calls[0], tt.want)
		})
	}
}

func TestCommandOpenerUsesExplicitBrowserPath(t *testing.T) {
	runner := &recordingCommandRunner{}
	opener := browser.CommandOpener{
		GOOS:   "linux",
		Runner: runner,
	}

	err := opener.Open(context.Background(), "https://admin.dev.example.com/auth/envvault/complete?code=opaque", "/tmp/fake-browser")

	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(runner.calls))
	}
	assertCommandCall(t, runner.calls[0], commandCall{
		name: "/tmp/fake-browser",
		args: []string{"https://admin.dev.example.com/auth/envvault/complete?code=opaque"},
	})
}

func TestCommandOpenerRejectsUnknownExplicitBrowser(t *testing.T) {
	runner := &recordingCommandRunner{}
	opener := browser.CommandOpener{
		GOOS:   "linux",
		Runner: runner,
	}

	err := opener.Open(context.Background(), "https://admin.dev.example.com/auth/envvault/complete?code=opaque", "lynx")
	if err == nil {
		t.Fatal("Open() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ConfigInvalid {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ConfigInvalid)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("calls = %d, want 0", len(runner.calls))
	}
}

func TestCommandOpenerRedactsLaunchURLWhenCommandFails(t *testing.T) {
	runner := &recordingCommandRunner{err: errors.New("failed to open https://admin.dev.example.com/auth/envvault/complete?code=opaque")}
	opener := browser.CommandOpener{
		GOOS:   "linux",
		Runner: runner,
	}

	err := opener.Open(context.Background(), "https://admin.dev.example.com/auth/envvault/complete?code=opaque", "")
	if err == nil {
		t.Fatal("Open() error = nil, want error")
	}
	if strings.Contains(err.Error(), "opaque") || strings.Contains(err.Error(), "complete?code=") {
		t.Fatalf("error leaked launch URL/code: %q", err.Error())
	}
	if code, _ := clerr.CodeOf(err); code != clerr.BrowserExchangeFailed {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.BrowserExchangeFailed)
	}
}

func TestCommandOpenerHonorsCanceledContextBeforeRunningCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &recordingCommandRunner{}
	opener := browser.CommandOpener{
		GOOS:   "linux",
		Runner: runner,
	}

	err := opener.Open(ctx, "https://admin.dev.example.com/auth/envvault/complete?code=opaque", "")
	if err == nil {
		t.Fatal("Open() error = nil, want context error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Open() error = %v, want context canceled", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("calls = %d, want 0", len(runner.calls))
	}
}

type commandCall struct {
	name string
	args []string
}

type recordingCommandRunner struct {
	calls []commandCall
	err   error
}

func (r *recordingCommandRunner) Run(_ context.Context, name string, args ...string) error {
	r.calls = append(r.calls, commandCall{name: name, args: append([]string(nil), args...)})
	return r.err
}

func assertCommandCall(t *testing.T, got, want commandCall) {
	t.Helper()
	if got.name != want.name {
		t.Fatalf("command name = %q, want %q", got.name, want.name)
	}
	if len(got.args) != len(want.args) {
		t.Fatalf("command args = %#v, want %#v", got.args, want.args)
	}
	for i := range got.args {
		if got.args[i] != want.args[i] {
			t.Fatalf("command args = %#v, want %#v", got.args, want.args)
		}
	}
}
