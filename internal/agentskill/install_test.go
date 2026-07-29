package agentskill_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trknhr/envvault/internal/agentskill"
)

func TestTargetPathUsesScopeAndAgentConventions(t *testing.T) {
	root := t.TempDir()
	tests := []struct {
		name    string
		options agentskill.TargetOptions
		want    string
	}{
		{
			name: "global universal",
			options: agentskill.TargetOptions{
				Scope:   agentskill.ScopeGlobal,
				Agent:   agentskill.AgentUniversal,
				HomeDir: root,
			},
			want: filepath.Join(root, ".agents", "skills", "envvault"),
		},
		{
			name: "global codex",
			options: agentskill.TargetOptions{
				Scope:   agentskill.ScopeGlobal,
				Agent:   agentskill.AgentCodex,
				HomeDir: root,
			},
			want: filepath.Join(root, ".codex", "skills", "envvault"),
		},
		{
			name: "global opencode",
			options: agentskill.TargetOptions{
				Scope:   agentskill.ScopeGlobal,
				Agent:   agentskill.AgentOpenCode,
				HomeDir: root,
			},
			want: filepath.Join(root, ".config", "opencode", "skills", "envvault"),
		},
		{
			name: "project universal",
			options: agentskill.TargetOptions{
				Scope:      agentskill.ScopeProject,
				Agent:      agentskill.AgentUniversal,
				ProjectDir: root,
			},
			want: filepath.Join(root, ".agents", "skills", "envvault"),
		},
		{
			name: "project claude code",
			options: agentskill.TargetOptions{
				Scope:      agentskill.ScopeProject,
				Agent:      agentskill.AgentClaudeCode,
				ProjectDir: root,
			},
			want: filepath.Join(root, ".claude", "skills", "envvault"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := agentskill.TargetPath(tt.options)
			if err != nil {
				t.Fatalf("TargetPath() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("TargetPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTargetPathRejectsUnsupportedOrRelativeTargets(t *testing.T) {
	for _, options := range []agentskill.TargetOptions{
		{Scope: agentskill.ScopeGlobal, Agent: "unknown", HomeDir: t.TempDir()},
		{Scope: agentskill.ScopeGlobal, Agent: agentskill.AgentUniversal, HomeDir: "relative"},
		{Scope: agentskill.ScopeProject, Agent: agentskill.AgentUniversal, ProjectDir: "relative"},
		{Scope: "workspace", Agent: agentskill.AgentUniversal, HomeDir: t.TempDir()},
	} {
		if _, err := agentskill.TargetPath(options); err == nil {
			t.Fatalf("TargetPath(%+v) error = nil", options)
		}
	}
}

func TestManagedSkillInstallStatusAndUninstallLifecycle(t *testing.T) {
	options := agentskill.TargetOptions{
		Scope:   agentskill.ScopeGlobal,
		Agent:   agentskill.AgentCodex,
		HomeDir: t.TempDir(),
	}

	before, err := agentskill.Inspect(options)
	if err != nil {
		t.Fatalf("Inspect(before) error = %v", err)
	}
	if before.State != agentskill.StateMissing {
		t.Fatalf("Inspect(before) state = %q, want missing", before.State)
	}

	first, err := agentskill.Install(options)
	if err != nil {
		t.Fatalf("Install(first) error = %v", err)
	}
	if !first.Changed || first.Status.State != agentskill.StateManaged || !first.Status.Current {
		t.Fatalf("Install(first) = %+v", first)
	}
	body, err := os.ReadFile(filepath.Join(first.Status.Path, "SKILL.md"))
	if err != nil {
		t.Fatalf("ReadFile(installed skill) error = %v", err)
	}
	if string(body) != agentskill.Stub() {
		t.Fatalf("installed skill differs from stub:\n%s", body)
	}

	second, err := agentskill.Install(options)
	if err != nil {
		t.Fatalf("Install(second) error = %v", err)
	}
	if second.Changed {
		t.Fatalf("Install(second) changed = true")
	}

	removed, err := agentskill.Uninstall(options)
	if err != nil {
		t.Fatalf("Uninstall() error = %v", err)
	}
	if !removed.Removed {
		t.Fatalf("Uninstall() = %+v", removed)
	}
	if _, err := os.Stat(removed.Path); !os.IsNotExist(err) {
		t.Fatalf("managed skill directory still exists or stat failed: %v", err)
	}
}

func TestManagedSkillRefusesToOverwriteOrRemoveUserChanges(t *testing.T) {
	options := agentskill.TargetOptions{
		Scope:   agentskill.ScopeGlobal,
		Agent:   agentskill.AgentUniversal,
		HomeDir: t.TempDir(),
	}
	result, err := agentskill.Install(options)
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	skillPath := filepath.Join(result.Status.Path, "SKILL.md")
	if err := os.WriteFile(skillPath, []byte(agentskill.Stub()+"\nuser change\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(user change) error = %v", err)
	}

	status, err := agentskill.Inspect(options)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if status.State != agentskill.StateManaged || !status.Modified {
		t.Fatalf("Inspect() = %+v, want modified managed skill", status)
	}
	if _, err := agentskill.Install(options); err == nil {
		t.Fatal("Install(modified) error = nil")
	}
	if _, err := agentskill.Uninstall(options); err == nil {
		t.Fatal("Uninstall(modified) error = nil")
	}
	body, err := os.ReadFile(skillPath)
	if err != nil {
		t.Fatalf("ReadFile(modified skill) error = %v", err)
	}
	if !strings.Contains(string(body), "user change") {
		t.Fatalf("modified skill was overwritten:\n%s", body)
	}
}

func TestExternalSkillIsPreserved(t *testing.T) {
	options := agentskill.TargetOptions{
		Scope:   agentskill.ScopeGlobal,
		Agent:   agentskill.AgentUniversal,
		HomeDir: t.TempDir(),
	}
	target, err := agentskill.TargetPath(options)
	if err != nil {
		t.Fatalf("TargetPath() error = %v", err)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll(target) error = %v", err)
	}
	external := "---\nname: envvault\ndescription: external\n---\n"
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte(external), 0o644); err != nil {
		t.Fatalf("WriteFile(external skill) error = %v", err)
	}

	status, err := agentskill.Inspect(options)
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if status.State != agentskill.StateExternal || status.Current {
		t.Fatalf("Inspect() = %+v, want different external skill", status)
	}
	if _, err := agentskill.Install(options); err == nil {
		t.Fatal("Install(external) error = nil")
	}
	if _, err := agentskill.Uninstall(options); err == nil {
		t.Fatal("Uninstall(external) error = nil")
	}
	body, err := os.ReadFile(filepath.Join(target, "SKILL.md"))
	if err != nil {
		t.Fatalf("ReadFile(external skill) error = %v", err)
	}
	if string(body) != external {
		t.Fatalf("external skill changed:\n%s", body)
	}
}

func TestCurrentExternalSkillIsRecognizedWithoutClaimingOwnership(t *testing.T) {
	options := agentskill.TargetOptions{
		Scope:   agentskill.ScopeGlobal,
		Agent:   agentskill.AgentUniversal,
		HomeDir: t.TempDir(),
	}
	target, err := agentskill.TargetPath(options)
	if err != nil {
		t.Fatalf("TargetPath() error = %v", err)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("MkdirAll(target) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte(agentskill.Stub()), 0o644); err != nil {
		t.Fatalf("WriteFile(external skill) error = %v", err)
	}

	result, err := agentskill.Install(options)
	if err != nil {
		t.Fatalf("Install(external current) error = %v", err)
	}
	if result.Changed || result.Status.State != agentskill.StateExternal || !result.Status.Current {
		t.Fatalf("Install(external current) = %+v", result)
	}
	if _, err := os.Stat(filepath.Join(target, ".envvault-managed.json")); !os.IsNotExist(err) {
		t.Fatalf("external skill marker exists or stat failed: %v", err)
	}
	if _, err := agentskill.Uninstall(options); err == nil {
		t.Fatal("Uninstall(external current) error = nil")
	}
}

func TestUninstallPreservesUnmanagedFilesInSkillDirectory(t *testing.T) {
	options := agentskill.TargetOptions{
		Scope:   agentskill.ScopeGlobal,
		Agent:   agentskill.AgentUniversal,
		HomeDir: t.TempDir(),
	}
	result, err := agentskill.Install(options)
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	notesPath := filepath.Join(result.Status.Path, "notes.txt")
	if err := os.WriteFile(notesPath, []byte("keep"), 0o644); err != nil {
		t.Fatalf("WriteFile(notes) error = %v", err)
	}

	if _, err := agentskill.Uninstall(options); err != nil {
		t.Fatalf("Uninstall() error = %v", err)
	}
	body, err := os.ReadFile(notesPath)
	if err != nil {
		t.Fatalf("ReadFile(notes) error = %v", err)
	}
	if string(body) != "keep" {
		t.Fatalf("notes = %q, want keep", body)
	}
}
