package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	managedmsb "github.com/trknhr/envvault/internal/runtime/microsandbox"
)

func TestProjectsHaveStableIsolatedStorageAndSymlinkAliasesMatch(t *testing.T) {
	state := t.TempDir()
	workspaceA, workspaceB := t.TempDir(), t.TempDir()
	a, err := newAgentProject(state, workspaceA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newAgentProject(state, workspaceB)
	if err != nil {
		t.Fatal(err)
	}
	if a.Volume() == b.Volume() || a.Sandbox() == b.Sandbox() || a.socket() == b.socket() {
		t.Fatal("independent workspaces share writable state")
	}
	if err := os.WriteFile(filepath.Join(a.dir, "fixture-history"), []byte("project A fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(b.dir, "fixture-history")); !os.IsNotExist(err) {
		t.Fatal("project B inherited project A state")
	}
	alias := filepath.Join(t.TempDir(), "workspace-alias")
	if err := os.Symlink(workspaceA, alias); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Go(func() {
			again, err := newAgentProject(state, alias)
			if err != nil {
				t.Error(err)
				return
			}
			if again.Project != a.Project || again.Volume() != a.Volume() {
				t.Error("workspace alias changed resume storage")
			}
		})
	}
	workers.Wait()
	info, err := os.Stat(a.dir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("project metadata is not private")
	}
}

func TestProjectMetadataCannotBeReboundToAnotherWorkspace(t *testing.T) {
	state := t.TempDir()
	a, err := newAgentProject(state, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := newAgentProject(state, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := os.ReadFile(filepath.Join(b.dir, "project.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.dir, "project.json"), foreign, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newAgentProject(state, a.Workspace); err == nil {
		t.Fatal("foreign workspace association accepted")
	}
}

func TestLegacyUnboundHomesAreNotAssignedToNewProjects(t *testing.T) {
	state := t.TempDir()
	legacy := filepath.Join(state, "agent.lock")
	if err := os.WriteFile(legacy, []byte("legacy data must remain\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := newAgentProject(state, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if p.Volume() == "envvault-msb-codex-home" || strings.Contains(p.Volume(), "parallel-") {
		t.Fatal("unbound legacy data was adopted")
	}
	if data, _ := os.ReadFile(legacy); string(data) != "legacy data must remain\n" {
		t.Fatal("legacy storage was changed")
	}
}

func TestProjectStateCannotBeRedirectedIntoGuestWorkspace(t *testing.T) {
	state, workspace := t.TempDir(), t.TempDir()
	identity, err := managedmsb.ProjectForWorkspace(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(state, "p"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(workspace, filepath.Join(state, "p", identity.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := newAgentProject(state, workspace); err == nil {
		t.Fatal("project metadata followed a guest-writable symlink")
	}
}
