package sandboxsession

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/trknhr/envvault/internal/sandboxplugin"
)

func TestReadBindingsFilesOverridesAndAliases(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sandbox.env")
	if err := os.WriteFile(file, []byte("# References only\nAPP_URL='envvault://unused/dev/base-url'\nAPP_TOKEN=envvault://api/dev/token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	bindings, err := ReadBindings(context.Background(), []string{file}, []string{
		"APP_URL=envvault://api/dev/base-url", "OTHER_URL=envvault://api/dev/base-url",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []sandboxplugin.Binding{{Profile: "api/dev", Outputs: []sandboxplugin.Output{
		{Environment: "APP_TOKEN", Part: sandboxplugin.OutputToken},
		{Environment: "APP_URL", Part: sandboxplugin.OutputBaseURL},
		{Environment: "OTHER_URL", Part: sandboxplugin.OutputBaseURL},
	}}}
	if !reflect.DeepEqual(bindings, want) {
		t.Fatalf("bindings = %#v", bindings)
	}
}

func TestReadBindingsRejectsUnsafeOrIncompleteInputs(t *testing.T) {
	valid := []string{"APP_URL=envvault://api/dev/base-url", "APP_TOKEN=envvault://api/dev/token"}
	for _, extra := range []string{
		"RAW=synthetic-secret-canary", "DIRECT=envvault://api/key", "PATH=envvault://api/dev/token",
		"NODE_OPTIONS=envvault://api/dev/token", "DOCKER_HOST=envvault://api/dev/token",
		"ENVVAULT_TALOS_SIGNING_KEY=envvault://api/dev/token", "AI_CONFIG=envvault://api/dev/token",
		"AGENT_INFRA_CONFIG=envvault://api/dev/token", "lower=envvault://api/dev/token", "INVALID",
	} {
		t.Run(strings.Split(extra, "=")[0], func(t *testing.T) {
			_, err := ReadBindings(context.Background(), nil, append(append([]string{}, valid...), extra))
			if err == nil || strings.Contains(err.Error(), "synthetic-secret-canary") {
				t.Fatalf("unsafe input was accepted or leaked: %v", err)
			}
		})
	}
	for _, entries := range [][]string{nil, valid[:1], {"APP_TOKEN=envvault://api/dev/token"},
		{"APP_URL=envvault://api/dev/base-url", "APP_TOKEN=envvault://different/dev/token"}} {
		if _, err := ReadBindings(context.Background(), nil, entries); err == nil {
			t.Fatal("incomplete bindings accepted")
		}
	}
	file := filepath.Join(t.TempDir(), "sandbox.env")
	if err := os.WriteFile(file, []byte(strings.Join(append(valid, "ENVVAULT_TALOS_SIGNING_KEY=secret-canary"), "\n")), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBindings(context.Background(), []string{file}, nil); err == nil {
		t.Fatal("reserved name from file accepted")
	}
}
