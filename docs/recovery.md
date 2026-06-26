# Recovery

This guide covers local recovery for EnvVault Local MVP.

## OS Credential Store Unavailable

Symptoms:

- `ENVVAULT_KEYRING_UNAVAILABLE`
- `ENVVAULT_KEYRING_LOCKED`
- `ENVVAULT_PARENT_KEY_MISSING`

Actions:

1. Unlock the platform credential store.
2. Re-run `envvault doctor`.
3. If only a profile parent key is missing, recreate that profile rather than adding a plaintext fallback.
4. Do not store parent keys in files.

## Corrupt or Missing SQLite

Symptoms:

- `envvault doctor` reports SQLite integrity or schema errors.
- Local parent-key metadata is unavailable.

Actions:

1. Preserve the existing data directory for investigation.
2. Restore from the migration backup if available.
3. If recovery is not possible, run `envvault reset --dry-run`, then `envvault reset --yes`, and initialize again.
4. Recreate profiles so parent keys and metadata match.

## Stale Runtime Lock or Crash

Symptoms:

- `ENVVAULT_LOCK_TIMEOUT`
- Doctor reports stale runtime state.
- A previous EnvVault process was killed during Talos startup or shutdown.

Actions:

1. Confirm no active `envvault` or managed Talos process is still running for the same user.
2. Run `envvault doctor`.
3. Run `envvault doctor --repair` to stop a recorded stale managed Talos process and remove stale EnvVault runtime locks and temporary files.
4. Re-run `envvault doctor` and investigate any remaining errors before starting another credential operation.

## JWKS Mismatch

Symptoms:

- Backends reject valid-looking tokens.
- `envvault issuer show` does not match backend configuration.
- Exported JWKS is missing or stale.

Actions:

1. Re-export JWKS:

```bash
envvault jwks export --output <backend-jwks-path>
```

2. Restart or reload the local backend.
3. Confirm the backend requires the expected issuer and resource.

## Suspected Secret Exposure

Actions:

1. Stop using affected profiles.
2. Reset or rotate affected parent keys.
3. Rotate downstream backend trust if signing material may be exposed.
4. Scan config, data, cache, logs, audit files, shell history, and temporary directories for the exposure marker.
5. Treat any valid leaked bearer token as usable until its expiry.

EnvVault cannot revoke application-side writes that already happened with a valid leased token.
