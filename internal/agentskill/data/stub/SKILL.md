---
name: envvault
description: Use when installing, configuring, upgrading, or running the EnvVault CLI; launching EnvVault Docker sandboxes; resolving envvault:// references; injecting isolated home files; configuring optional API proxies or outbound profiles; or debugging EnvVault setup.
---

# EnvVault

This is a discovery stub. Load the instructions bundled with the installed
EnvVault CLI before using EnvVault commands.

## Start here

1. Check whether `envvault` is available.
2. If it is missing:
   - When the user explicitly asked to install or set up EnvVault, install it
     with the supported package manager. On macOS or Linux with Homebrew, run
     `brew install trknhr/tap/envvault`.
   - Otherwise, explain that EnvVault must be installed and ask before changing
     system-wide packages.
3. Load the version-matched instructions:

```bash
envvault skills get core
```

If `skills get core` is unavailable, the CLI predates bundled agent
instructions. When the user explicitly requested installation, setup, or an
upgrade, update EnvVault with `brew update` followed by
`brew upgrade trknhr/tap/envvault`, then retry. Otherwise, explain that an
upgrade is required and ask before changing system-wide packages.

Follow the returned instructions for the rest of the task. Do not guess commands
from a cached copy of this stub. Never print credential values while checking
the installation or exercising EnvVault.
