// Package sandbox defines runtime-neutral sandbox lifecycle orchestration.
// Runtime specifications contain only values that may be delivered to an
// untrusted sandbox; raw upstream credentials must never be included.
package sandbox

import (
	"context"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/connection"
)

type Runtime interface {
	Name() string
	Check(ctx context.Context) error
	Create(ctx context.Context, spec Spec) (Sandbox, error)
}

// GatewayAccess describes how a host gateway can be reached from a runtime.
// A runtime that does not implement GatewayAccessor uses host loopback.
type GatewayAccess struct {
	ListenAddress string
	AdvertiseHost string
}

type GatewayAccessor interface {
	GatewayAccess() GatewayAccess
}

// EgressAttachment is the runtime-specific, secretless wiring required to use
// a trusted outbound broker. Environment values may contain a short-lived
// capability but never an upstream credential.
type EgressAttachment struct {
	Environment map[string]string
	Mounts      []Mount
	Resources   []Resource
	Mode        EgressMode
}

type EgressMode string

const (
	// EgressProxyEnvironment preserves application destination URLs but relies
	// on the application honoring the standard HTTP proxy environment.
	EgressProxyEnvironment EgressMode = "proxy-environment"
)

// EgressAttacher is implemented by runtimes that know how to expose a broker
// endpoint and trust bundle to their workload without exposing the upstream
// credential. Network enforcement remains a separate runtime responsibility.
type EgressAttacher interface {
	AttachEgress(ctx context.Context, config connection.EgressClientConfig) (EgressAttachment, error)
}

type Sandbox interface {
	ID() string
	Start(ctx context.Context) error
	Wait(ctx context.Context) (ExitResult, error)
	Stop(ctx context.Context) error
	Remove(ctx context.Context) error
}

type Resource interface {
	Close(ctx context.Context) error
}

type ExitResult struct {
	Code int
}

type Spec struct {
	Image            string
	Command          []string
	WorkingDirectory string
	Environment      map[string]string
	Workspace        WorkspaceMount
	Mounts           []Mount
	PublishedPorts   []PortPublication
	Resources        ResourceLimits
	Network          NetworkAttachment
	Gateway          connection.Endpoint
	SecurityLevel    connection.SecurityLevel
	Stdin            io.Reader
	Stdout           io.Writer
	Stderr           io.Writer
	Interactive      bool
	TTY              bool
}

type WorkspaceMount struct {
	Source   string
	Target   string
	ReadOnly bool
}

// Mount is a runtime-neutral directory mount prepared by a trusted adapter.
// Callers must raise the security level when the directory contains credential
// material.
type Mount struct {
	Source   string
	Target   string
	ReadOnly bool
}

type PortPublication struct {
	ContainerPort uint16
}

type PublishedPort struct {
	ContainerPort uint16
	HostAddress   string
}

type PortPublisher interface {
	PublishedPorts(ctx context.Context) ([]PublishedPort, error)
}

type ResourceLimits struct {
	PIDs        int
	MemoryBytes int64
	CPUs        float64
}

type NetworkMode string

const NetworkBridge NetworkMode = "bridge"

type NetworkAttachment struct {
	Mode NetworkMode
}

func (s Spec) Validate() error {
	if strings.TrimSpace(s.Image) == "" {
		return configInvalid("sandbox image is required")
	}
	if strings.HasPrefix(s.Image, "-") || strings.IndexByte(s.Image, 0) >= 0 {
		return configInvalid("sandbox image is invalid")
	}
	if len(s.Command) == 0 || strings.TrimSpace(s.Command[0]) == "" {
		return configInvalid("sandbox command is required")
	}
	for _, argument := range s.Command {
		if strings.IndexByte(argument, 0) >= 0 {
			return configInvalid("sandbox command contains a null byte")
		}
	}
	if strings.TrimSpace(s.WorkingDirectory) == "" || !path.IsAbs(s.WorkingDirectory) {
		return configInvalid("sandbox working directory must be absolute")
	}
	if strings.TrimSpace(s.Workspace.Source) == "" || !filepath.IsAbs(s.Workspace.Source) {
		return configInvalid("sandbox workspace source must be absolute")
	}
	if strings.TrimSpace(s.Workspace.Target) == "" || !path.IsAbs(s.Workspace.Target) {
		return configInvalid("sandbox workspace target must be absolute")
	}
	mountTargets := map[string]struct{}{path.Clean(s.Workspace.Target): {}}
	for _, mount := range s.Mounts {
		if strings.TrimSpace(mount.Source) == "" || !filepath.IsAbs(mount.Source) || strings.IndexByte(mount.Source, 0) >= 0 {
			return configInvalid("sandbox mount source must be absolute")
		}
		if strings.TrimSpace(mount.Target) == "" || !path.IsAbs(mount.Target) || path.Clean(mount.Target) == "/" || strings.IndexByte(mount.Target, 0) >= 0 {
			return configInvalid("sandbox mount target must be an absolute non-root path")
		}
		target := path.Clean(mount.Target)
		if _, exists := mountTargets[target]; exists {
			return configInvalid("sandbox mount targets must be unique")
		}
		workspaceTarget := path.Clean(s.Workspace.Target)
		if strings.HasPrefix(target+"/", workspaceTarget+"/") || strings.HasPrefix(workspaceTarget+"/", target+"/") {
			return configInvalid("sandbox mount target must not overlap the workspace")
		}
		mountTargets[target] = struct{}{}
	}
	if s.Network.Mode != NetworkBridge {
		return configInvalid("sandbox network mode must be bridge")
	}
	if s.Resources.PIDs < 0 || s.Resources.MemoryBytes < 0 || s.Resources.CPUs < 0 {
		return configInvalid("sandbox resource limits must not be negative")
	}
	for key, value := range s.Environment {
		if !validEnvironmentName(key) {
			return configInvalid("sandbox environment variable name is invalid")
		}
		if strings.IndexByte(value, 0) >= 0 {
			return configInvalid("sandbox environment value contains a null byte")
		}
	}
	for _, publication := range s.PublishedPorts {
		if publication.ContainerPort == 0 {
			return configInvalid("sandbox published container port is required")
		}
	}
	if (s.Gateway.Network == "") != (s.Gateway.Address == "") {
		return configInvalid("sandbox gateway endpoint is incomplete")
	}
	switch s.SecurityLevel {
	case connection.SecurityBrokered, connection.SecurityMaterializedStatic:
	default:
		return configInvalid("sandbox security level is invalid for the experimental runtime")
	}
	return nil
}

func validEnvironmentName(name string) bool {
	if name == "" || strings.ContainsRune(name, '=') || strings.IndexByte(name, 0) >= 0 {
		return false
	}
	for i, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

func configInvalid(message string) error {
	return clerr.New(clerr.ConfigInvalid, message)
}

// Keep os imported with the lifecycle-facing types so callers use the same
// signal type without runtime-specific adapters.
type Signal = os.Signal
