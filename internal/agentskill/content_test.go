package agentskill_test

import (
	"strings"
	"testing"

	"github.com/trknhr/envvault/internal/agentskill"
)

func TestBundledCoreSkillContainsVersionMatchedWorkflow(t *testing.T) {
	content, err := agentskill.Get(agentskill.CoreName)
	if err != nil {
		t.Fatalf("Get(core) error = %v", err)
	}
	for _, want := range []string{
		"name: core",
		"envvault credential set <credential-name>",
		"envvault exec --env-file .env -- <command>",
		"--home-file <destination>=<source>",
		"--outbound-profile <proxy-name>",
		"`--all`",
		"late-bound",
		"EnvVault-specific tool",
		"Do not print credential-bearing environment values",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("core skill missing %q:\n%s", want, content)
		}
	}
	for _, forbidden := range []string{"secret-canary", "Authorization: Bearer"} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("core skill contains forbidden marker %q", forbidden)
		}
	}
}

func TestDiscoveryStubLoadsBundledCoreAndGatesInstallation(t *testing.T) {
	stub := agentskill.Stub()
	for _, want := range []string{
		"name: envvault",
		"envvault skills get core",
		"brew install trknhr/tap/envvault",
		"explicitly asked to install or set up EnvVault",
		"ask before changing",
	} {
		if !strings.Contains(stub, want) {
			t.Fatalf("stub missing %q:\n%s", want, stub)
		}
	}
	if strings.Contains(stub, "--home-file <destination>=<source>") {
		t.Fatalf("stub unexpectedly contains the full workflow:\n%s", stub)
	}
}

func TestGetRejectsUnknownBundledSkill(t *testing.T) {
	if _, err := agentskill.Get("missing"); err == nil {
		t.Fatal("Get(missing) error = nil")
	}
}
