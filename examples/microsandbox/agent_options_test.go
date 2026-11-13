package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAgentWorkspaceIsCurrentProjectAndExplicitArgumentsStaySeparate(t *testing.T) {
	workspace := t.TempDir()
	t.Chdir(workspace)
	canonical, _ := filepath.EvalSymlinks(workspace)
	options, err := parseAgentOptions([]string{"codex", "--model", "fixture", "prompt with spaces"})
	if err != nil || options.workspace != canonical || !reflect.DeepEqual(options.args, []string{"--model", "fixture", "prompt with spaces"}) {
		t.Fatalf("current project not selected: %v", err)
	}
	other := t.TempDir()
	otherCanonical, _ := filepath.EvalSymlinks(other)
	alias := filepath.Join(workspace, "project-alias")
	if err := os.Symlink(other, alias); err != nil {
		t.Fatal(err)
	}
	options, err = parseAgentOptions([]string{"codex", "--workspace", alias, "--", "--workspace", "guest-only-argument"})
	if err != nil || options.workspace != otherCanonical || !reflect.DeepEqual(options.args, []string{"--workspace", "guest-only-argument"}) {
		t.Fatal("host workspace and guest arguments were confused")
	}
	file := filepath.Join(workspace, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"codex", "--workspace"}, {"codex", "--workspace="}, {"codex", "--workspace", file}, {"codex", "--workspace", filepath.Join(workspace, "missing")}} {
		if _, err := parseAgentOptions(args); err == nil {
			t.Fatal("invalid workspace was accepted")
		}
	}
}

func TestConcurrentFirstLaunchPolicyInitialization(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "agent-policy.json")
	results := make(chan error, 4)
	for i := 0; i < cap(results); i++ {
		go func() {
			_, err := prepareAgentHost(t.Context(), dir, policy, "rules")
			results <- err
		}()
	}
	for i := 0; i < cap(results); i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestInstalledImageAssetsDoNotDependOnCurrentDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	dir, cleanup, err := agentBuildContext()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for _, file := range []string{"Dockerfile", "agent-entrypoint", "git-credential-envvault", ".dockerignore"} {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil || len(data) == 0 {
			t.Fatalf("installed image asset unavailable: %s", file)
		}
	}
	data, err := agentAssets.ReadFile("agent-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policy, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAgentPolicy(policy); err != nil {
		t.Fatal("embedded policy default is invalid")
	}
}
