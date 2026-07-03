package cli

import (
	"fmt"
	"io"
	"strings"
)

func helpTarget(args []string) ([]string, bool) {
	if len(args) == 0 {
		return nil, false
	}
	if isHelpFlag(args[0]) {
		return nil, true
	}
	if args[0] == "help" {
		return append([]string(nil), args[1:]...), true
	}
	for i, arg := range args {
		if arg == "--" {
			return nil, false
		}
		if isHelpFlag(arg) {
			return append([]string(nil), args[:i]...), true
		}
	}
	return nil, false
}

func isHelpFlag(arg string) bool {
	return arg == "--help" || arg == "-h"
}

func writeHelp(target []string, stdout, stderr io.Writer) int {
	text, ok := helpText(target)
	if !ok {
		fmt.Fprintln(stderr, "envvault: unknown help topic")
		return 2
	}
	fmt.Fprint(stdout, text)
	return 0
}

func helpText(target []string) (string, bool) {
	target = normalizeHelpTarget(target)
	key := strings.Join(target, " ")
	switch key {
	case "":
		return rootHelp, true
	case "credential", "credential add", "credential list":
		return credentialHelp, true
	case "profile", "profile list":
		return profileHelp, true
	case "proxy", "proxy add":
		return proxyHelp, true
	case "inject", "inject add":
		return injectHelp, true
	case "exec":
		return execHelp, true
	case "admin":
		return adminHelp, true
	case "list":
		return listHelp, true
	case "version":
		return versionHelp, true
	}
	return "", false
}

func normalizeHelpTarget(target []string) []string {
	out := make([]string, 0, len(target))
	for _, item := range target {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

const rootHelp = `EnvVault keeps real credentials in the OS credential store and resolves envvault:// references at process launch.

Usage:
  envvault <command> [options]
  envvault help [command]

Common commands:
  envvault admin start
  envvault credential add <name> --value-stdin
  envvault credential list
  envvault proxy add <name> --credential <credential> --target <url> --allow-path <path> --allow-method <method>
  envvault inject add <name> --credential <credential>
  envvault profile list
  envvault exec --env KEY=envvault://profile/output -- <command>
  envvault version

Run "envvault <command> --help" for command help.
`

const credentialHelp = `Usage:
  envvault credential add <name> --value-stdin
  envvault credential list

Commands:
  add     Store a credential value in the OS credential store.
  list    Print credential names only. Values are never displayed.

Example:
  printf 'secret\n' | envvault credential add openai-key/dev --value-stdin
`

const profileHelp = `Usage:
  envvault profile list

Commands:
  list    Print profile metadata without credential values.

Profile creation:
  envvault proxy add <name> --credential <credential> [options]
  envvault inject add <name> --credential <credential> [options]
`

const proxyHelp = `Usage:
  envvault proxy add <name> --credential <credential> --target <url> --allow-path <path> --allow-method <method> [options]

Options:
  --credential <name>       Credential name stored by envvault credential add.
  --provider <provider>     generic or openai-compatible. Default: generic.
  --target <url>            Provider base URL.
  --allow-path <path>       Allowed request path. Repeatable.
  --allow-method <method>   Allowed request method. Repeatable.
  --project-binding <mode>  none, path-hash, or git-remote-and-root.

The command prints envvault://.../base-url and envvault://.../token references.
`

const injectHelp = `Usage:
  envvault inject add <name> --credential <credential> [options]

Options:
  --credential <name>       Credential name stored by envvault credential add.
  --project-binding <mode>  none, path-hash, or git-remote-and-root.

Inject is the default compatibility path. It passes the raw credential value to the child process.
`

const execHelp = `Usage:
  envvault exec --env-file .env -- <command>
  envvault exec --env KEY=VALUE -- <command>

Options:
  --env-file <path>  Read KEY=VALUE entries from a dotenv file. Repeatable.
  --env KEY=VALUE    Add one environment value without creating a file. Repeatable.

Examples:
  envvault exec --env-file .env -- npm run dev
  envvault exec --env OPENAI_BASE_URL=envvault://openai/dev/base-url --env OPENAI_API_KEY=envvault://openai/dev/token -- npm run dev
`

const adminHelp = `Usage:
  envvault admin start [--addr <host:port>]
  envvault admin status
  envvault admin stop

Commands:
  start   Start the local browser UI.
  status  Print local admin server status.
  stop    Stop the local admin server.
`

const listHelp = `Usage:
  envvault list credentials
  envvault list profiles

Aliases:
  envvault credential list
  envvault profile list
`

const versionHelp = `Usage:
  envvault version
  envvault --version

Print the EnvVault CLI version.
`
