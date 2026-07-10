package cli

import (
	"fmt"
	"io"
	"strings"
)

const versionUsage = "envvault: usage: envvault version"

var (
	version = "dev"
	commit  = ""
)

func runVersion(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, versionUsage)
		return 2
	}
	fmt.Fprint(stdout, versionOutput())
	return 0
}

func versionOutput() string {
	value := strings.TrimSpace(version)
	if value == "" {
		value = "dev"
	}
	revision := strings.TrimSpace(commit)
	if revision == "" {
		return fmt.Sprintf("envvault %s\n", value)
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	return fmt.Sprintf("envvault %s (%s)\n", value, revision)
}
