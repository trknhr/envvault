// Package sandboxsession connects credential leases to processes in existing
// sandboxes. Unlike sandbox.Runtime, a session never owns container removal.
package sandboxsession

import (
	"context"
	"io"

	"github.com/trknhr/envvault/internal/sandbox"
	"github.com/trknhr/envvault/internal/sandboxplugin"
)

type Target struct {
	Reference   string
	Directory   string
	Interactive bool
	ParentEnv   []string
}

type Prepared struct {
	ID      string
	Target  Target
	Project sandboxplugin.ProjectIdentity
	Gateway sandbox.GatewayAccess
}

type Command struct {
	Args        []string
	Environment map[string]string
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
}

type Runtime interface {
	Prepare(context.Context, Target) (Prepared, error)
	Run(context.Context, Prepared, Command) (int, error)
}
