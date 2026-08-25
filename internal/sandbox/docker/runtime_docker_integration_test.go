package docker_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/sandbox"
	sandboxdocker "github.com/trknhr/envvault/internal/sandbox/docker"
)

func TestDockerRuntimePublishesLoopbackPortAndRemovesContainer(t *testing.T) {
	requireDockerIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	runtime := sandboxdocker.New(sandboxdocker.Options{})
	if err := runtime.Check(ctx); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	var stdout, stderr bytes.Buffer
	spec := dockerIntegrationSpec(t, dockerIntegrationImage(), []string{
		"node", "--eval", strings.Join([]string{
			`const http = require("http");`,
			`const server = http.createServer((request, response) => {`,
			`response.end("envvault-publish-ok");`,
			`server.close(() => process.exit(0));`,
			`});`,
			`server.listen(3000, "0.0.0.0", () => console.log("ready"));`,
			`setTimeout(() => process.exit(7), 15000);`,
		}, ""),
	})
	spec.PublishedPorts = []sandbox.PortPublication{{ContainerPort: 3000}}
	spec.Stdout = &stdout
	spec.Stderr = &stderr
	instance, err := runtime.Create(ctx, spec)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	sandboxID := instance.ID()
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_ = instance.Remove(cleanupCtx)
	})
	if err := instance.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	publisher, ok := instance.(sandbox.PortPublisher)
	if !ok {
		t.Fatalf("sandbox type %T does not implement PortPublisher", instance)
	}
	ports, err := publisher.PublishedPorts(ctx)
	if err != nil {
		t.Fatalf("PublishedPorts() error = %v", err)
	}
	if len(ports) != 1 || ports[0].ContainerPort != 3000 || !strings.HasPrefix(ports[0].HostAddress, "127.0.0.1:") {
		t.Fatalf("PublishedPorts() = %#v", ports)
	}

	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(10 * time.Second)
	var body []byte
	for time.Now().Before(deadline) {
		response, requestErr := client.Get("http://" + ports[0].HostAddress)
		if requestErr == nil {
			body, requestErr = io.ReadAll(response.Body)
			_ = response.Body.Close()
			if requestErr == nil && response.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if string(body) != "envvault-publish-ok" {
		t.Fatalf("published response = %q; stdout=%q stderr=%q", body, stdout.String(), stderr.String())
	}
	exit, err := instance.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait() error = %v; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if exit.Code != 0 {
		t.Fatalf("exit code = %d; stdout=%q stderr=%q", exit.Code, stdout.String(), stderr.String())
	}
	if err := instance.Remove(ctx); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	assertDockerContainerRemoved(t, ctx, sandboxID)
}

func TestDockerRuntimeInterruptStopsAndRemovesContainer(t *testing.T) {
	requireDockerIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	runtime := sandboxdocker.New(sandboxdocker.Options{})
	signals := make(chan sandbox.Signal, 1)
	signals <- os.Interrupt
	var sandboxID string

	result, err := (sandbox.Orchestrator{CleanupTimeout: 5 * time.Second}).Run(ctx, sandbox.RunRequest{
		Runtime: runtime,
		Spec: dockerIntegrationSpec(t, dockerIntegrationImage(), []string{
			"node", "--eval", `setInterval(() => {}, 1000);`,
		}),
		Signals: signals,
		OnCreated: func(id string, _ connection.SecurityLevel) {
			sandboxID = id
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !result.Interrupted || sandboxID == "" {
		t.Fatalf("Run() result/id = %#v/%q", result, sandboxID)
	}
	assertDockerContainerRemoved(t, ctx, sandboxID)
}

func TestDockerRuntimePersistsNestedHomeMount(t *testing.T) {
	requireDockerIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	state := t.TempDir()
	spec := dockerIntegrationSpec(t, dockerIntegrationImage(), []string{
		"node", "--eval", `require("fs").writeFileSync(process.env.CODEX_HOME + "/auth.json", "persisted")`,
	})
	spec.Environment["CODEX_HOME"] = "/home/envvault/.codex"
	spec.Mounts = []sandbox.Mount{{Source: state, Target: "/home/envvault/.codex"}}
	spec.SecurityLevel = connection.SecurityMaterializedStatic
	var sandboxID string

	result, err := (sandbox.Orchestrator{CleanupTimeout: 5 * time.Second}).Run(ctx, sandbox.RunRequest{
		Runtime: sandboxdocker.New(sandboxdocker.Options{}),
		Spec:    spec,
		OnCreated: func(id string, _ connection.SecurityLevel) {
			sandboxID = id
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.ExitCode != 0 || sandboxID == "" {
		t.Fatalf("Run() result/id = %#v/%q", result, sandboxID)
	}
	contents, err := os.ReadFile(filepath.Join(state, "auth.json"))
	if err != nil || string(contents) != "persisted" {
		t.Fatalf("persistent mount contents = %q/%v", contents, err)
	}
	assertDockerContainerRemoved(t, ctx, sandboxID)
}

func dockerIntegrationSpec(t *testing.T, image string, command []string) sandbox.Spec {
	t.Helper()
	return sandbox.Spec{
		Image:            image,
		Command:          command,
		WorkingDirectory: "/workspace",
		Environment:      map[string]string{"TEST_MODE": "docker-integration"},
		Workspace: sandbox.WorkspaceMount{
			Source: t.TempDir(),
			Target: "/workspace",
		},
		Network:       sandbox.NetworkAttachment{Mode: sandbox.NetworkBridge},
		SecurityLevel: connection.SecurityBrokered,
		Stdout:        io.Discard,
		Stderr:        io.Discard,
	}
}

func dockerIntegrationImage() string {
	if image := strings.TrimSpace(os.Getenv("ENVVAULT_DOCKER_TEST_IMAGE")); image != "" {
		return image
	}
	return "node:22-slim"
}

func requireDockerIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("ENVVAULT_DOCKER_TEST") != "1" {
		t.Skip("set ENVVAULT_DOCKER_TEST=1 to run Docker integration tests")
	}
}

func assertDockerContainerRemoved(t *testing.T, ctx context.Context, sandboxID string) {
	t.Helper()
	output, err := exec.CommandContext(ctx, "docker", "ps", "-aq", "--filter", "label=io.envvault.sandbox="+sandboxID).Output()
	if err != nil {
		t.Fatalf("docker ps error = %v", err)
	}
	if strings.TrimSpace(string(output)) != "" {
		t.Fatalf("sandbox container remained after run: %q", output)
	}
}
