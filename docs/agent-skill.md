# Agent Skill

EnvVault ships its agent integration in two layers:

1. A small discovery `SKILL.md` makes EnvVault discoverable to compatible
   agents.
2. The complete `core` instructions are bundled with the EnvVault binary.

The discovery skill tells the agent to run:

```bash
envvault skills get core
```

Because the complete instructions come from the installed binary, they match
the available EnvVault commands after `brew upgrade`.

## CLI-First Installation

Install EnvVault, then install the discovery skill:

```bash
brew install trknhr/tap/envvault
envvault skills install
```

`skills install` is an explicit request to modify the selected agent skill
directory. It copies only the discovery stub; it does not invoke `npm`, `npx`,
or another installer.

The default scope is global. Without `--agent`, EnvVault installs to the
cross-client location:

```text
~/.agents/skills/envvault/SKILL.md
```

Choose a native agent location when needed:

```bash
envvault skills install --agent codex
envvault skills install --agent claude-code
envvault skills install --agent cursor
envvault skills install --agent github-copilot
envvault skills install --agent opencode
```

Use `--project` to install at the current project root:

```bash
envvault skills install --project --agent codex
```

For most agents, the project target is `.agents/skills/envvault`. Claude Code
uses `.claude/skills/envvault`.

## Skill-First Installation

The public repository remains installable with the `skills` CLI:

```bash
npx skills add trknhr/envvault --skill envvault -g -a codex
```

From a local checkout:

```bash
npx skills add . --skill envvault
```

This route installs the same discovery stub. When the agent activates it, the
stub first checks whether `envvault` is available.

- If the user explicitly asked to install or set up EnvVault, the agent may
  install the CLI with the supported package manager.
- For any other request, the agent explains that the CLI is required and asks
  before changing system-wide packages.

Skill activation alone must not silently install software.

## Inspect Bundled Content

List instructions bundled with the installed CLI:

```bash
envvault skills list
```

Print the version-matched core instructions:

```bash
envvault skills get core
```

Inspect a discovery skill installation:

```bash
envvault skills status --agent codex
envvault skills path --agent codex
```

`status` distinguishes EnvVault-managed installations from external
installations such as those managed by `npx skills`.

## Upgrade

Upgrade the CLI and its bundled instructions together:

```bash
brew update
brew upgrade trknhr/tap/envvault
```

No separate update is required for the complete `core` instructions. The
installed discovery stub is intentionally small and stable. Re-run
`envvault skills install` if a future release reports that its managed stub is
out of date.

For a discovery stub installed through `npx skills`, update that externally
managed file with:

```bash
npx skills update envvault -g
```

Restart the agent after installing or changing the discovery stub. An already
running session may retain instructions that were loaded earlier.

## Ownership and Uninstall

EnvVault records ownership only for discovery skills created by
`envvault skills install`. It updates and removes those managed files, but
refuses to overwrite or delete a different skill owned by another installer.

Remove an EnvVault-managed global skill:

```bash
envvault skills uninstall
```

For a project installation, repeat the original scope:

```bash
envvault skills uninstall --project --agent codex
```

If `npx skills` installed the skill, remove it through the same tool:

```bash
npx skills remove envvault -g -a codex
```
