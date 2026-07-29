package agentskill

import (
	_ "embed"
	"fmt"
	"strings"
)

const (
	Name     = "envvault"
	CoreName = "core"
)

//go:embed data/core/SKILL.md
var coreSkill string

//go:embed data/stub/SKILL.md
var discoveryStub string

type Descriptor struct {
	Name        string
	Description string
}

func List() []Descriptor {
	return []Descriptor{{
		Name:        CoreName,
		Description: "Version-matched EnvVault CLI workflows and safety guidance",
	}}
}

func Get(name string) (string, error) {
	switch strings.TrimSpace(name) {
	case CoreName:
		return normalized(coreSkill), nil
	default:
		return "", fmt.Errorf("unknown bundled skill %q", name)
	}
}

func Stub() string {
	return normalized(discoveryStub)
}

func normalized(content string) string {
	return strings.TrimSpace(content) + "\n"
}
