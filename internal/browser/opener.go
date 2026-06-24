package browser

import (
	"context"
	"os/exec"
	"runtime"
	"strings"

	"github.com/trknhr/credlease/internal/clerr"
)

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) error
}

type CommandOpener struct {
	GOOS   string
	Runner CommandRunner
}

func (o CommandOpener) Open(ctx context.Context, rawURL string, browser string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	command, err := o.command(rawURL, browser)
	if err != nil {
		return err
	}
	runner := o.Runner
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	if err := runner.Run(ctx, command.name, command.args...); err != nil {
		return clerr.Wrap(clerr.BrowserExchangeFailed, "open browser command failed", errRedacted{})
	}
	return nil
}

func (o CommandOpener) command(rawURL string, browserName string) (browserCommand, error) {
	if strings.TrimSpace(rawURL) == "" {
		return browserCommand{}, clerr.New(clerr.BrowserURLRejected, "launch url is required")
	}
	if explicitPath := strings.TrimSpace(browserName); isExplicitBrowserPath(explicitPath) {
		return browserCommand{name: explicitPath, args: []string{rawURL}}, nil
	}
	browserName = normalizeBrowserName(browserName)
	goos := o.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	switch goos {
	case "darwin":
		return darwinCommand(rawURL, browserName)
	case "windows":
		return windowsCommand(rawURL, browserName)
	default:
		return linuxCommand(rawURL, browserName)
	}
}

type ExecCommandRunner struct{}

func (ExecCommandRunner) Run(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

type browserCommand struct {
	name string
	args []string
}

func darwinCommand(rawURL, browserName string) (browserCommand, error) {
	switch browserName {
	case "":
		return browserCommand{name: "open", args: []string{rawURL}}, nil
	case "chrome":
		return browserCommand{name: "open", args: []string{"-a", "Google Chrome", rawURL}}, nil
	default:
		return browserCommand{}, unsupportedBrowser(browserName)
	}
}

func linuxCommand(rawURL, browserName string) (browserCommand, error) {
	switch browserName {
	case "":
		return browserCommand{name: "xdg-open", args: []string{rawURL}}, nil
	case "chrome":
		return browserCommand{name: "google-chrome", args: []string{rawURL}}, nil
	case "chromium":
		return browserCommand{name: "chromium-browser", args: []string{rawURL}}, nil
	default:
		return browserCommand{}, unsupportedBrowser(browserName)
	}
}

func windowsCommand(rawURL, browserName string) (browserCommand, error) {
	switch browserName {
	case "":
		return browserCommand{name: "rundll32", args: []string{"url.dll,FileProtocolHandler", rawURL}}, nil
	case "chrome":
		return browserCommand{name: "cmd", args: []string{"/c", "start", "", "chrome", rawURL}}, nil
	default:
		return browserCommand{}, unsupportedBrowser(browserName)
	}
}

func normalizeBrowserName(browserName string) string {
	name := strings.ToLower(strings.TrimSpace(browserName))
	switch name {
	case "google-chrome", "google chrome":
		return "chrome"
	case "chromium-browser":
		return "chromium"
	default:
		return name
	}
}

func isExplicitBrowserPath(browserName string) bool {
	return strings.Contains(browserName, "/") || strings.Contains(browserName, `\`)
}

func unsupportedBrowser(browserName string) error {
	return clerr.New(clerr.ConfigInvalid, "unsupported browser name")
}

type errRedacted struct{}

func (errRedacted) Error() string {
	return "browser command failed"
}
