# Uninstall

Uninstall removes EnvVault-owned local state. It must not delete repository
files.

## Preferred Reset

Preview removal:

```bash
envvault reset --dry-run
```

Remove EnvVault config, data, cache, and known OS credential store entries:

```bash
envvault reset --yes
```

## Manual Cleanup

Use this only if `envvault reset` is unavailable.

1. Remove EnvVault config, data, and cache directories for the current OS user.
2. Delete OS credential store entries with these account names:

```text
envvault/credential/<credential-name>/value
```

3. Remove `envvault://` references from project `.env` files if those projects
   no longer use EnvVault.

Do not remove repository files as part of EnvVault cleanup unless you
intentionally own that project change.

## Verification

Run:

```bash
envvault doctor
```

After uninstall, missing config and keyring entries are expected.
