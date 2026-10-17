# Recovery

This guide covers local recovery for EnvVault.

## OS Credential Store Unavailable

Symptoms:

- `ENVVAULT_KEYRING_UNAVAILABLE`
- `ENVVAULT_KEYRING_LOCKED`
- Credential add, credential resolution, or proxy use fails while reading the OS
  credential store.

Actions:

1. Unlock the platform credential store.
2. Re-run `envvault doctor`.
3. Re-add affected credentials if the platform credential store entry is missing.
4. Do not store credentials in repository files as a fallback.

## Move or Restore Secrets

Use an encrypted export when secrets have to move to another machine, or when a
local credential store has to be rebuilt.

```bash
envvault export secrets.envault
envvault import secrets.envault
```

Import skips names that already exist unless `--overwrite` is set. The file
does not contain Talos signing keys or profile parent keys, so process and
browser profiles still need those keys created on the destination. See
[Export and import](/export).

## Corrupt or Missing Local State

Symptoms:

- `envvault doctor` reports config, data, cache, or SQLite integrity errors.
- Optional proxies cannot be loaded.

Actions:

1. Preserve the existing data directory for investigation.
2. Restore from the migration backup if available.
3. If recovery is not possible, run `envvault reset --dry-run`, then
   `envvault reset --yes`.
4. Recreate credentials and optional proxies.

## Stale Runtime Lock or Crash

Symptoms:

- `ENVVAULT_LOCK_TIMEOUT`
- Doctor reports stale runtime state.
- A previous EnvVault process was killed while starting or stopping local
  runtime state.

Actions:

1. Confirm no active `envvault` process is still running for the same user.
2. Run `envvault doctor`.
3. Run `envvault doctor --repair` to remove stale EnvVault runtime locks and
   temporary files.
4. Re-run `envvault doctor` and investigate any remaining errors before starting
   another credential operation.

## Suspected Secret Exposure

Actions:

1. Stop using affected credentials or proxies.
2. Rotate affected credentials in the upstream service.
3. Re-add the rotated value to EnvVault.
4. Scan config, data, cache, logs, audit files, shell history, and temporary
   directories for the exposure marker.
5. Treat any leaked local proxy token as usable until the child process exits or
   the token expires.

EnvVault cannot revoke application-side writes that already happened with a
valid credential.
