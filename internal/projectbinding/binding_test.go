package projectbinding_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/profile"
	"github.com/trknhr/credlease/internal/projectbinding"
)

func TestCheckAllowsProjectBindingNone(t *testing.T) {
	err := projectbinding.Check(profile.ProjectBinding{
		Mode: profile.ProjectBindingNone,
	}, projectbinding.Identity{
		Root:      filepath.Join(t.TempDir(), "repo"),
		GitRemote: "git@example.com:team/repo.git",
	})

	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
}

func TestApprovePathHashAndCheckRejectsMovedProject(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	binding, err := projectbinding.Approve(profile.ProjectBindingPathHash, projectbinding.Identity{
		Root: root,
	})
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	if binding.Mode != profile.ProjectBindingPathHash {
		t.Fatalf("Mode = %q, want path-hash", binding.Mode)
	}
	if binding.PathHash == "" || !strings.HasPrefix(binding.PathHash, "sha256:") {
		t.Fatalf("PathHash = %q, want sha256 value", binding.PathHash)
	}
	if strings.Contains(binding.PathHash, root) {
		t.Fatalf("PathHash leaked raw root path: %q", binding.PathHash)
	}
	if err := projectbinding.Check(binding, projectbinding.Identity{Root: root}); err != nil {
		t.Fatalf("Check(approved root) error = %v", err)
	}

	err = projectbinding.Check(binding, projectbinding.Identity{Root: filepath.Join(t.TempDir(), "repo")})
	if err == nil {
		t.Fatal("Check(moved root) error = nil, want project not trusted")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ProjectNotTrusted {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ProjectNotTrusted)
	}
}

func TestGitRemoteAndRootBindingRequiresBothRemoteAndRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	binding, err := projectbinding.Approve(profile.ProjectBindingGitRemoteAndRoot, projectbinding.Identity{
		Root:      root,
		GitRemote: "git@example.com:team/repo.git",
	})
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	if binding.GitRoot != root {
		t.Fatalf("GitRoot = %q, want %q", binding.GitRoot, root)
	}
	if binding.GitRemote != "git@example.com:team/repo.git" {
		t.Fatalf("GitRemote = %q", binding.GitRemote)
	}
	if err := projectbinding.Check(binding, projectbinding.Identity{Root: root, GitRemote: "git@example.com:team/repo.git"}); err != nil {
		t.Fatalf("Check(approved identity) error = %v", err)
	}

	tests := []projectbinding.Identity{
		{Root: root, GitRemote: "git@example.com:team/other.git"},
		{Root: filepath.Join(t.TempDir(), "repo"), GitRemote: "git@example.com:team/repo.git"},
		{Root: root},
	}
	for _, tt := range tests {
		t.Run(tt.Root+" "+tt.GitRemote, func(t *testing.T) {
			err := projectbinding.Check(binding, tt)
			if err == nil {
				t.Fatal("Check() error = nil, want project not trusted")
			}
			if code, _ := clerr.CodeOf(err); code != clerr.ProjectNotTrusted {
				t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ProjectNotTrusted)
			}
		})
	}
}

func TestCheckRejectsUnapprovedBinding(t *testing.T) {
	err := projectbinding.Check(profile.ProjectBinding{
		Mode: profile.ProjectBindingPathHash,
	}, projectbinding.Identity{
		Root: filepath.Join(t.TempDir(), "repo"),
	})

	if err == nil {
		t.Fatal("Check() error = nil, want project not trusted")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ProjectNotTrusted {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ProjectNotTrusted)
	}
	if strings.Contains(err.Error(), "secret-canary") {
		t.Fatalf("error leaked secret marker: %q", err.Error())
	}
}

func TestDetectFindsGitRootAndOriginRemote(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	start := filepath.Join(root, "nested", "pkg")
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatalf("MkdirAll(.git) error = %v", err)
	}
	if err := os.MkdirAll(start, 0o700); err != nil {
		t.Fatalf("MkdirAll(start) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "config"), []byte(`[remote "origin"]
	url = git@example.com:team/repo.git
`), 0o600); err != nil {
		t.Fatalf("WriteFile(config) error = %v", err)
	}

	identity, err := projectbinding.Detect(context.Background(), start)

	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if identity.Root != root {
		t.Fatalf("Root = %q, want %q", identity.Root, root)
	}
	if identity.GitRemote != "git@example.com:team/repo.git" {
		t.Fatalf("GitRemote = %q", identity.GitRemote)
	}
}

func TestDetectUsesStartDirectoryWhenNoGitRootExists(t *testing.T) {
	start := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(start, 0o700); err != nil {
		t.Fatalf("MkdirAll(start) error = %v", err)
	}

	identity, err := projectbinding.Detect(context.Background(), start)

	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if identity.Root != start {
		t.Fatalf("Root = %q, want %q", identity.Root, start)
	}
	if identity.GitRemote != "" {
		t.Fatalf("GitRemote = %q, want empty", identity.GitRemote)
	}
}
