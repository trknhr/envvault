package agentskill

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	ScopeGlobal  = "global"
	ScopeProject = "project"

	AgentUniversal     = "universal"
	AgentCodex         = "codex"
	AgentClaudeCode    = "claude-code"
	AgentCursor        = "cursor"
	AgentGitHubCopilot = "github-copilot"
	AgentOpenCode      = "opencode"

	skillFilename  = "SKILL.md"
	markerFilename = ".envvault-managed.json"
	markerSchema   = 1
)

type TargetOptions struct {
	Scope      string
	Agent      string
	HomeDir    string
	ProjectDir string
}

type State string

const (
	StateMissing  State = "not-installed"
	StateManaged  State = "managed"
	StateExternal State = "external"
)

type Status struct {
	Path     string
	State    State
	Current  bool
	Modified bool
}

type InstallResult struct {
	Status  Status
	Changed bool
}

type UninstallResult struct {
	Path    string
	Removed bool
}

type managedMarker struct {
	Schema        int    `json:"schema"`
	ContentSHA256 string `json:"content_sha256"`
}

func SupportedAgents() []string {
	return []string{
		AgentUniversal,
		AgentCodex,
		AgentClaudeCode,
		AgentCursor,
		AgentGitHubCopilot,
		AgentOpenCode,
	}
}

func TargetPath(options TargetOptions) (string, error) {
	scope := strings.TrimSpace(options.Scope)
	if scope == "" {
		scope = ScopeGlobal
	}
	agent, err := normalizeAgent(options.Agent)
	if err != nil {
		return "", err
	}

	var root string
	switch scope {
	case ScopeGlobal:
		root = strings.TrimSpace(options.HomeDir)
		if root == "" {
			return "", fmt.Errorf("home directory is required for global skill installation")
		}
		if !filepath.IsAbs(root) {
			return "", fmt.Errorf("home directory must be absolute")
		}
	case ScopeProject:
		root = strings.TrimSpace(options.ProjectDir)
		if root == "" {
			return "", fmt.Errorf("project directory is required for project skill installation")
		}
		if !filepath.IsAbs(root) {
			return "", fmt.Errorf("project directory must be absolute")
		}
	default:
		return "", fmt.Errorf("unknown skill scope %q", scope)
	}

	base, err := skillBase(scope, agent)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Clean(root), base, Name), nil
}

func Inspect(options TargetOptions) (Status, error) {
	path, err := TargetPath(options)
	if err != nil {
		return Status{}, err
	}
	return inspectPath(path)
}

func Install(options TargetOptions) (InstallResult, error) {
	status, err := Inspect(options)
	if err != nil {
		return InstallResult{}, err
	}

	switch status.State {
	case StateMissing:
		if err := writeManagedSkill(status.Path); err != nil {
			return InstallResult{}, err
		}
		installed, err := inspectPath(status.Path)
		return InstallResult{Status: installed, Changed: true}, err
	case StateManaged:
		if status.Modified {
			return InstallResult{}, fmt.Errorf("managed skill was modified; refusing to overwrite %s", status.Path)
		}
		if status.Current {
			return InstallResult{Status: status}, nil
		}
		if err := writeManagedSkill(status.Path); err != nil {
			return InstallResult{}, err
		}
		installed, err := inspectPath(status.Path)
		return InstallResult{Status: installed, Changed: true}, err
	case StateExternal:
		if status.Current {
			return InstallResult{Status: status}, nil
		}
		return InstallResult{}, fmt.Errorf("existing skill is managed externally; refusing to overwrite %s", status.Path)
	default:
		return InstallResult{}, fmt.Errorf("unknown skill installation state %q", status.State)
	}
}

func Uninstall(options TargetOptions) (UninstallResult, error) {
	status, err := Inspect(options)
	if err != nil {
		return UninstallResult{}, err
	}
	if status.State == StateMissing {
		return UninstallResult{Path: status.Path}, nil
	}
	if status.State != StateManaged {
		return UninstallResult{}, fmt.Errorf("skill is managed externally; refusing to remove %s", status.Path)
	}
	if status.Modified {
		return UninstallResult{}, fmt.Errorf("managed skill was modified; refusing to remove %s", status.Path)
	}

	skillPath := filepath.Join(status.Path, skillFilename)
	if err := os.Remove(skillPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return UninstallResult{}, fmt.Errorf("remove managed skill: %w", err)
	}
	markerPath := filepath.Join(status.Path, markerFilename)
	if err := os.Remove(markerPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return UninstallResult{}, fmt.Errorf("remove managed skill marker: %w", err)
	}
	if err := os.Remove(status.Path); err != nil && !errors.Is(err, os.ErrNotExist) && !isDirectoryNotEmpty(err) {
		return UninstallResult{}, fmt.Errorf("remove empty skill directory: %w", err)
	}
	return UninstallResult{Path: status.Path, Removed: true}, nil
}

func normalizeAgent(agent string) (string, error) {
	switch strings.TrimSpace(agent) {
	case "", AgentUniversal, "agents":
		return AgentUniversal, nil
	case AgentCodex:
		return AgentCodex, nil
	case AgentClaudeCode, "claude":
		return AgentClaudeCode, nil
	case AgentCursor:
		return AgentCursor, nil
	case AgentGitHubCopilot, "copilot":
		return AgentGitHubCopilot, nil
	case AgentOpenCode, "open-code":
		return AgentOpenCode, nil
	default:
		return "", fmt.Errorf("unsupported agent %q (supported: %s)", agent, strings.Join(SupportedAgents(), ", "))
	}
}

func skillBase(scope, agent string) (string, error) {
	if scope == ScopeProject {
		switch agent {
		case AgentClaudeCode:
			return filepath.Join(".claude", "skills"), nil
		case AgentUniversal, AgentCodex, AgentCursor, AgentGitHubCopilot, AgentOpenCode:
			return filepath.Join(".agents", "skills"), nil
		}
	}
	if scope == ScopeGlobal {
		switch agent {
		case AgentUniversal:
			return filepath.Join(".agents", "skills"), nil
		case AgentCodex:
			return filepath.Join(".codex", "skills"), nil
		case AgentClaudeCode:
			return filepath.Join(".claude", "skills"), nil
		case AgentCursor:
			return filepath.Join(".cursor", "skills"), nil
		case AgentGitHubCopilot:
			return filepath.Join(".copilot", "skills"), nil
		case AgentOpenCode:
			return filepath.Join(".config", "opencode", "skills"), nil
		}
	}
	return "", fmt.Errorf("unsupported skill target %s/%s", scope, agent)
}

func inspectPath(path string) (Status, error) {
	status := Status{Path: path, State: StateMissing}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return status, nil
	}
	if err != nil {
		return Status{}, fmt.Errorf("inspect skill directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		status.State = StateExternal
		status.Current = installedContentMatches(path)
		return status, nil
	}
	if !info.IsDir() {
		return Status{}, fmt.Errorf("skill path is not a directory: %s", path)
	}

	body, bodyErr := os.ReadFile(filepath.Join(path, skillFilename))
	if errors.Is(bodyErr, os.ErrNotExist) {
		if _, markerErr := os.Stat(filepath.Join(path, markerFilename)); markerErr == nil {
			return Status{
				Path:     path,
				State:    StateManaged,
				Modified: true,
			}, nil
		}
		return status, nil
	}
	if bodyErr != nil {
		return Status{}, fmt.Errorf("read installed skill: %w", bodyErr)
	}
	actualHash := contentSHA256(body)
	status.Current = actualHash == contentSHA256([]byte(Stub()))

	marker, markerErr := readMarker(filepath.Join(path, markerFilename))
	if errors.Is(markerErr, os.ErrNotExist) {
		status.State = StateExternal
		return status, nil
	}
	if markerErr != nil {
		status.State = StateExternal
		return status, nil
	}
	status.State = StateManaged
	status.Modified = marker.ContentSHA256 != actualHash && !status.Current
	return status, nil
}

func installedContentMatches(path string) bool {
	body, err := os.ReadFile(filepath.Join(path, skillFilename))
	return err == nil && contentSHA256(body) == contentSHA256([]byte(Stub()))
}

func writeManagedSkill(path string) error {
	if !filepath.IsAbs(path) || filepath.Base(path) != Name || filepath.Base(filepath.Dir(path)) != "skills" {
		return fmt.Errorf("refusing unsafe skill path %q", path)
	}
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(path, 0o755); err != nil {
			return fmt.Errorf("create skill directory: %w", err)
		}
	case err != nil:
		return fmt.Errorf("inspect skill directory: %w", err)
	case info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("refusing to write through skill directory symlink: %s", path)
	case !info.IsDir():
		return fmt.Errorf("skill path is not a directory: %s", path)
	}

	body := []byte(Stub())
	if err := writeAtomic(filepath.Join(path, skillFilename), body, 0o644); err != nil {
		return err
	}
	markerBody, err := json.Marshal(managedMarker{
		Schema:        markerSchema,
		ContentSHA256: contentSHA256(body),
	})
	if err != nil {
		return fmt.Errorf("encode managed skill marker: %w", err)
	}
	markerBody = append(markerBody, '\n')
	if err := writeAtomic(filepath.Join(path, markerFilename), markerBody, 0o644); err != nil {
		return err
	}
	return nil
}

func readMarker(path string) (managedMarker, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return managedMarker{}, err
	}
	var marker managedMarker
	if err := json.Unmarshal(body, &marker); err != nil {
		return managedMarker{}, fmt.Errorf("decode managed skill marker: %w", err)
	}
	if marker.Schema != markerSchema || len(marker.ContentSHA256) != sha256.Size*2 {
		return managedMarker{}, fmt.Errorf("invalid managed skill marker")
	}
	return marker, nil
}

func contentSHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func writeAtomic(path string, body []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".envvault-skill-*")
	if err != nil {
		return fmt.Errorf("create temporary skill file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return fmt.Errorf("set temporary skill file permissions: %w", err)
	}
	if _, err := temp.Write(body); err != nil {
		temp.Close()
		return fmt.Errorf("write temporary skill file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary skill file: %w", err)
	}
	if err := os.Rename(tempPath, path); err == nil {
		return nil
	} else if runtime.GOOS != "windows" {
		return fmt.Errorf("install skill file: %w", err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("replace skill file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("install skill file: %w", err)
	}
	return nil
}

func isDirectoryNotEmpty(err error) bool {
	return errors.Is(err, os.ErrExist) || strings.Contains(strings.ToLower(err.Error()), "directory not empty")
}
