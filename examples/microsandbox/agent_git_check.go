package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	m "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/profile"
)

// All Git traffic in agent-check terminates at this disposable local fixture.
// No GitHub account, existing repository, or real credential is used.
func prepareAgentGitCheck(dir string) (http.Handler, error) {
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, errors.New("agent-check requires host git")
	}
	root := filepath.Join(dir, "git-origin")
	bare := filepath.Join(root, "envvault-check", "repository.git")
	seed := filepath.Join(dir, "git-seed")
	if err := os.MkdirAll(filepath.Dir(bare), 0700); err != nil {
		return nil, err
	}
	environment := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	run := func(args ...string) error {
		command := exec.Command(git, args...)
		command.Env = environment
		if command.Run() != nil {
			return errors.New("cannot prepare disposable Git fixture")
		}
		return nil
	}
	for _, args := range [][]string{{"init", "--bare", bare}, {"init", seed}, {"-C", seed, "config", "user.name", "EnvVault Check"}, {"-C", seed, "config", "user.email", "check@envvault.invalid"}} {
		if err := run(args...); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(seed, "hello.txt"), []byte("local fixture\n"), 0600); err != nil {
		return nil, err
	}
	for _, args := range [][]string{{"-C", seed, "add", "hello.txt"}, {"-C", seed, "commit", "-m", "Local fixture"}, {"-C", seed, "push", bare, "HEAD:refs/heads/main"}, {"-C", bare, "symbolic-ref", "HEAD", "refs/heads/main"}} {
		if err := run(args...); err != nil {
			return nil, err
		}
	}
	return &cgi.Handler{Path: git, Args: []string{"http-backend"}, Dir: dir,
		Env: append(environment, "GIT_PROJECT_ROOT="+root, "GIT_HTTP_EXPORT_ALL=1", "REMOTE_USER=envvault-check"), Logger: log.New(io.Discard, "", 0)}, nil
}

func checkAgentGit(ctx context.Context, sb *m.Sandbox, check *agentCredentialCheck) error {
	paths, _ := connection.GitHTTPSPaths("envvault-check/repository", false)
	gitProfile := config.Profile{Kind: profile.KindProviderProxy, CredentialName: "microsandbox/check", Provider: "generic", TargetURL: "https://github.com",
		AllowedMethods: []string{"GET", "POST"}, AllowedPaths: paths, LocalTokenTTL: config.Duration(time.Minute)}
	check.config.Profiles["git-check"] = gitProfile
	if err := config.Save(check.filename, check.config); err != nil {
		return err
	}
	if err := waitAgentCatalogRoute(ctx, sb, "/envvault-check/repository.git/info/refs"); err != nil {
		return err
	}
	const prefix = "GIT_TERMINAL_PROMPT=0 GIT_CONFIG_GLOBAL=/dev/null git "
	if _, err := checkedAgentShell(ctx, sb, prefix+"clone --quiet https://github.com/envvault-check/repository.git /tmp/envvault-git-check"); err != nil {
		return errors.New("Git clone did not authenticate through the host proxy")
	}
	if err := check.rotate(ctx); err != nil {
		return err
	}
	if _, err := checkedAgentShell(ctx, sb, prefix+"ls-remote https://github.com/envvault-check/repository.git HEAD >/dev/null"); err != nil {
		return errors.New("Git credential rotation did not apply live")
	}
	if _, err := checkedAgentShell(ctx, sb, "cd /tmp/envvault-git-check && printf 'guest change\\n' >> hello.txt && "+prefix+"-c user.name=EnvVault -c user.email=check@envvault.invalid commit -qam 'Local sandbox check'"); err != nil {
		return err
	}
	const push = prefix + "-C /tmp/envvault-git-check push --quiet origin HEAD:refs/heads/agent-check"
	if _, err := checkedAgentShell(ctx, sb, push); err == nil || check.gitWrites.Load() != 0 {
		return errors.New("read-only Git profile allowed a push")
	}
	gitProfile.AllowedPaths, _ = connection.GitHTTPSPaths("envvault-check/repository", true)
	check.config.Profiles["git-check"] = gitProfile
	if err := config.Save(check.filename, check.config); err != nil {
		return err
	}
	if _, err := checkedAgentShell(ctx, sb, push); err != nil || check.gitWrites.Load() == 0 {
		return errors.New("host Git write permission did not apply live")
	}
	if _, err := checkedAgentShell(ctx, sb, prefix+"ls-remote https://github.com/envvault-check/other.git HEAD >/dev/null"); err == nil {
		return errors.New("Git profile escaped its repository scope")
	}
	if _, err := checkedAgentShell(ctx, sb, "! grep -Rq 'test-only-' /tmp/envvault-git-check/.git && rm -rf /tmp/envvault-git-check"); err != nil {
		return errors.New("Git retained a test credential")
	}
	fmt.Println("PASS: Git clone and local push use host-only credentials; repository and live read/write rules are enforced")
	return nil
}

func waitAgentCatalogRoute(ctx context.Context, sb *m.Sandbox, path string) error {
	for attempt := 0; attempt < 30; attempt++ {
		if _, err := checkedAgentShell(ctx, sb, "grep -Fq '"+path+"' \"$ENVVAULT_CREDENTIALS_FILE\""); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("Git route did not reach the public guest catalog")
}
