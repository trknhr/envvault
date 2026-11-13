package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/trknhr/envvault/internal/config"
)

type sandboxReleaseTransport func(*http.Request) (*http.Response, error)

func (f sandboxReleaseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSandboxCodexAutomaticallyInstallsMatchingReleaseAfterCLIUpgrade(t *testing.T) {
	if runtime.GOOS != "linux" && (runtime.GOOS != "darwin" || runtime.GOARCH != "arm64") {
		t.Skip("requires a supported POSIX Microsandbox host")
	}
	previous := version
	t.Cleanup(func() { version = previous })
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "envvault-microsandbox"), []byte("#!/bin/sh\nprintf unverified-PATH-helper\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	requests := 0
	client := &http.Client{Transport: sandboxReleaseTransport(func(req *http.Request) (*http.Response, error) {
		requests++
		base := "https://github.com/trknhr/envvault/releases/download/" + version + "/"
		name := "envvault-microsandbox_" + version + "_" + runtime.GOOS + "_" + runtime.GOARCH
		payload := "#!/bin/sh\nprintf 'verified-" + version + "\\n'\n"
		body := payload
		if req.URL.String() == base+"MICROSANDBOX_SHA256SUMS" {
			body = fmt.Sprintf("%x  %s\n", sha256.Sum256([]byte(payload)), name)
		} else if req.URL.String() != base+name {
			t.Fatalf("unexpected download: %s", req.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	app := New(Options{ProjectStartDir: t.TempDir(), Paths: config.Paths{DataDir: t.TempDir()}, SandboxHelperHTTP: client, Stdin: strings.NewReader("")})
	for _, release := range []string{"v9.8.7", "v9.8.8"} {
		version = release
		for attempt := 0; attempt < 2; attempt++ {
			var out, stderr bytes.Buffer
			if code := app.Run(context.Background(), []string{"sandbox", "codex", "--version"}, &out, &stderr); code != 0 || out.String() != "verified-"+release+"\n" {
				t.Fatalf("wrong helper after CLI upgrade: %s %s", &out, &stderr)
			}
		}
	}
	if requests != 4 {
		t.Fatalf("cached launches should not download again: %d requests", requests)
	}
}
