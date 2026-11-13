package microsandbox

import (
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
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func testManager(t *testing.T) Manager {
	t.Helper()
	if err := supportedPlatform(); err != nil {
		t.Skip(err)
	}
	return Manager{Dir: t.TempDir(), Version: "v1.2.3"}
}

func releaseClient(t *testing.T, version, payload, checksum string, status int) (*http.Client, *int) {
	t.Helper()
	calls := new(int)
	name := Helper + "_" + version + "_" + runtime.GOOS + "_" + runtime.GOARCH
	return &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		(*calls)++
		if req.URL.Scheme != "https" || req.URL.Host != "github.com" || req.Method != http.MethodGet {
			t.Fatalf("unexpected release request: %s %s", req.Method, req.URL)
		}
		var body string
		switch req.URL.String() {
		case releaseBase + version + "/MICROSANDBOX_SHA256SUMS":
			body = checksum + "  " + name + "\n"
		case releaseBase + version + "/" + name:
			body = payload
		default:
			t.Fatalf("request was not pinned to the CLI release: %s", req.URL)
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}, calls
}

func TestReleaseInstallVerifiesBytesAndReusesMatchingHelperOffline(t *testing.T) {
	m := testManager(t)
	const binary = "native helper fixture"
	var calls *int
	m.HTTP, calls = releaseClient(t, m.Version, binary, fmt.Sprintf("%x", sha256.Sum256([]byte(binary))), 200)
	path, err := m.Install(context.Background(), "", false)
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != binary {
		t.Fatal("wrong helper installed")
	}
	if *calls != 2 {
		t.Fatal("release installation did not fetch checksums and a binary")
	}
	m.HTTP = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("cached helper attempted a network request")
		return nil, nil
	})}
	if again, err := m.Install(context.Background(), "", false); err != nil || again != path {
		t.Fatalf("offline reuse failed: %v", err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Resolve(); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatal("modified helper was accepted")
	}
	upgraded := m
	upgraded.Version = "v1.2.4"
	if _, err := upgraded.Resolve(); !os.IsNotExist(err) {
		t.Fatal("new CLI reused an older helper")
	}
}

func TestInstallRejectsSymlinkedVersionDirectory(t *testing.T) {
	m := testManager(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(m.Dir, m.Version)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Install(context.Background(), "", false); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatal("followed a symlinked installation directory")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatal("installer wrote through the symlink")
	}
}

func TestFailedReleaseInstallPreservesWorkingHelper(t *testing.T) {
	for _, kind := range []string{"checksum", "missing release", "missing checksum"} {
		t.Run(kind, func(t *testing.T) {
			m := testManager(t)
			fixture := filepath.Join(t.TempDir(), Helper)
			if err := os.WriteFile(fixture, []byte("existing helper"), 0700); err != nil {
				t.Fatal(err)
			}
			previous, err := m.Install(context.Background(), fixture, false)
			if err != nil {
				t.Fatal(err)
			}
			sum, status := strings.Repeat("0", 64), 200
			if kind == "missing release" {
				status = 404
			} else if kind == "missing checksum" {
				sum = "invalid"
			}
			m.HTTP, _ = releaseClient(t, m.Version, "new helper", sum, status)
			if _, err := m.Install(context.Background(), "", true); err == nil {
				t.Fatal("invalid release was installed")
			}
			if current, err := m.Resolve(); err != nil || current != previous {
				t.Fatal("failed install replaced the previous helper")
			}
			dir, _ := m.versionDir()
			stages, _ := filepath.Glob(filepath.Join(dir, ".install-*"))
			if len(stages) != 0 {
				t.Fatal("temporary download was left behind")
			}
		})
	}
}

func TestLocalDevelopmentInstallUpdatesWithoutChangingExistingBinary(t *testing.T) {
	m := testManager(t)
	m.Version = "dev"
	source := filepath.Join(t.TempDir(), Helper)
	if err := os.WriteFile(source, []byte("first helper"), 0700); err != nil {
		t.Fatal(err)
	}
	first, err := m.Install(context.Background(), source, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("second helper"), 0700); err != nil {
		t.Fatal(err)
	}
	second, err := m.Install(context.Background(), source, false)
	if err != nil || first == second {
		t.Fatal("updated development helper was not selected")
	}
	if data, _ := os.ReadFile(first); string(data) != "first helper" {
		t.Fatal("updating changed a running session's helper")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Install(ctx, source, false); err == nil {
		t.Fatal("cancelled setup succeeded")
	}
	if current, err := m.Resolve(); err != nil || current != second {
		t.Fatal("cancelled setup replaced installed helper")
	}
}

func TestReleaseRejectsUnsafeRedirectAndDuplicateChecksum(t *testing.T) {
	m := testManager(t)
	m.HTTP = &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"http://example.com/helper"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	if _, err := m.Install(context.Background(), "", false); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatal("insecure release redirect was accepted")
	}
	sum := strings.Repeat("a", 64) + "  helper\n"
	if _, err := checksumFor(sum+sum, "helper"); err == nil {
		t.Fatal("ambiguous checksums were accepted")
	}
	for _, invalid := range []string{"../bad", "v1.2.3/../../bad", "latest"} {
		m.Version = invalid
		if _, err := m.Install(context.Background(), "", false); err == nil {
			t.Fatal("unsafe or unpinned release version was accepted")
		}
	}
}
