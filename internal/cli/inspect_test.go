package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trknhr/envvault/internal/cli"
	"github.com/trknhr/envvault/internal/credentialscan"
)

func TestRunInspectNeverPrintsCredentialValue(t *testing.T) {
	root := t.TempDir()
	secret := inspectSyntheticGitHubToken()
	path := filepath.Join(root, ".env")
	if err := os.WriteFile(path, []byte("GITHUB_TOKEN="+secret+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	app := cli.New(cli.Options{})
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := app.Run(context.Background(), []string{"inspect", "--path", root, "--format", format}, &stdout, &stderr)

			if code != 0 {
				t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
			}
			combined := stdout.String() + stderr.String()
			if strings.Contains(combined, secret) {
				t.Fatalf("Run() output exposed credential value")
			}
			if !strings.Contains(stdout.String(), "github-pat") {
				t.Fatalf("stdout = %q, want Gitleaks rule", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}
		})
	}
}

func TestRunInspectJSONContainsOnlySafeFindingMetadata(t *testing.T) {
	root := t.TempDir()
	secret := inspectSyntheticGitHubToken()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("GITHUB_TOKEN="+secret+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	app := cli.New(cli.Options{})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"inspect", "--path", root, "--format", "json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	var result credentialscan.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; stdout=%q", err, stdout.String())
	}
	if len(result.Findings) == 0 {
		t.Fatalf("result = %#v, want finding", result)
	}
	if result.Findings[0].Path == "" || result.Findings[0].RuleID == "" {
		t.Fatalf("finding = %#v, want safe metadata", result.Findings[0])
	}
}

func TestRunInspectFailOnFindings(t *testing.T) {
	root := t.TempDir()
	secret := inspectSyntheticGitHubToken()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("GITHUB_TOKEN="+secret+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	app := cli.New(cli.Options{})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"inspect", "--path", root, "--fail-on-findings"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("Run() code = %d, want 1", code)
	}
	if stdout.Len() == 0 {
		t.Fatal("stdout is empty, want findings")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunInspectIncludesMediumFindings(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "settings.toml"), []byte("password = \"blue-horse-blue-horse\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	app := cli.New(cli.Options{})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"inspect", "--path", root, "--include-medium"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "envvault/secret-field") {
		t.Fatalf("stdout = %q, want semantic finding", stdout.String())
	}
}

func TestRunInspectReportsPathOnlyFindingForSkippedBinary(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "client.p12")
	if err := os.WriteFile(path, []byte{0, 1, 2}, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	app := cli.New(cli.Options{})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"inspect", "--path", root}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	for _, want := range []string{"pkcs12-file", "high", "skipped 1 path."} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunInspectShowsSkippedPathsOnlyWhenVerbose(t *testing.T) {
	root := t.TempDir()
	skippedName := "credential-cache.bin"
	if err := os.WriteFile(filepath.Join(root, skippedName), []byte{0, 1, 2}, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	app := cli.New(cli.Options{})

	t.Run("text default", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := app.Run(context.Background(), []string{"inspect", "--path", root}, &stdout, &stderr)

		if code != 0 {
			t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "skipped 1 path.") {
			t.Fatalf("stdout = %q, want skipped count", stdout.String())
		}
		if strings.Contains(stdout.String(), skippedName) || strings.Contains(stdout.String(), "SKIPPED") {
			t.Fatalf("stdout = %q, did not want skipped details", stdout.String())
		}
	})

	t.Run("text verbose", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := app.Run(context.Background(), []string{"inspect", "--path", root, "--verbose"}, &stdout, &stderr)

		if code != 0 {
			t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), skippedName) || !strings.Contains(stdout.String(), "binary") {
			t.Fatalf("stdout = %q, want skipped details", stdout.String())
		}
	})

	t.Run("json default", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := app.Run(context.Background(), []string{"inspect", "--path", root, "--format", "json"}, &stdout, &stderr)

		if code != 0 {
			t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
		}
		var result map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("json.Unmarshal() error = %v", err)
		}
		if result["paths_skipped"] != float64(1) {
			t.Fatalf("paths_skipped = %#v, want 1", result["paths_skipped"])
		}
		if _, ok := result["skipped"]; ok {
			t.Fatalf("result = %#v, did not want skipped details", result)
		}
	})

	t.Run("json verbose", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := app.Run(context.Background(), []string{
			"inspect", "--path", root, "--format", "json", "--verbose",
		}, &stdout, &stderr)

		if code != 0 {
			t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
		}
		var result map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("json.Unmarshal() error = %v", err)
		}
		if _, ok := result["skipped"]; !ok {
			t.Fatalf("result = %#v, want skipped details", result)
		}
	})
}

func TestRunInspectRejectsUnknownFormat(t *testing.T) {
	app := cli.New(cli.Options{})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"inspect", "--format", "yaml"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("Run() code = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "text or json") {
		t.Fatalf("stderr = %q, want format error", stderr.String())
	}
}

func TestRunInspectHelpShowsDepthAndWorkers(t *testing.T) {
	app := cli.New(cli.Options{})
	var stdout, stderr bytes.Buffer

	code := app.Run(context.Background(), []string{"inspect", "--help"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("Run() code = %d, want 0; stderr=%q", code, stderr.String())
	}
	for _, want := range []string{
		"--depth int",
		"Maximum nested directory depth",
		"--workers int",
		"Concurrent file scanners",
		"--verbose",
		"Show every skipped path",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
}

func TestRunInspectRejectsInvalidDepthAndWorkers(t *testing.T) {
	app := cli.New(cli.Options{})
	for _, args := range [][]string{
		{"inspect", "--depth", "-1"},
		{"inspect", "--workers", "-1"},
		{"inspect", "--workers", "33"},
	} {
		var stdout, stderr bytes.Buffer

		code := app.Run(context.Background(), args, &stdout, &stderr)

		if code != 2 {
			t.Fatalf("Run(%v) code = %d, want 2", args, code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("Run(%v) stdout = %q, want empty", args, stdout.String())
		}
		if !strings.Contains(stderr.String(), "ENVVAULT_CONFIG_INVALID") {
			t.Fatalf("Run(%v) stderr = %q, want config error", args, stderr.String())
		}
	}
}

func inspectSyntheticGitHubToken() string {
	return "ghp_" + "A1b2C3d4E5f6G7h8" + "I9j0K1l2M3n4O5p6Q7r8"
}
