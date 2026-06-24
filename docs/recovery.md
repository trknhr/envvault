# Recovery

This guide covers local recovery for Credlease Local MVP.

## OS Credential Store Unavailable

Symptoms:

- `CREDLEASE_KEYRING_UNAVAILABLE`
- `CREDLEASE_KEYRING_LOCKED`
- `CREDLEASE_PARENT_KEY_MISSING`

Actions:

1. Unlock the platform credential store.
2. Re-run `credlease doctor`.
3. If only a profile parent key is missing, recreate that profile rather than adding a plaintext fallback.
4. Do not store parent keys in files.

## Corrupt or Missing SQLite

Symptoms:

- `credlease doctor` reports SQLite integrity or schema errors.
- Local parent-key metadata is unavailable.

Actions:

1. Preserve the existing data directory for investigation.
2. Restore from the migration backup if available.
3. If recovery is not possible, run `credlease reset --dry-run`, then `credlease reset --yes`, and initialize again.
4. Recreate profiles so parent keys and metadata match.

## Stale Runtime Lock or Crash

Symptoms:

- `CREDLEASE_LOCK_TIMEOUT`
- Doctor reports stale runtime state.
- A previous Credlease process was killed during Talos startup or shutdown.

Actions:

1. Confirm no active `credlease` or managed Talos process is still running for the same user.
2. Run `credlease doctor`.
3. Run `credlease doctor --repair` to stop a recorded stale managed Talos process and remove stale Credlease runtime locks and temporary files.
4. Re-run `credlease doctor` and investigate any remaining errors before starting another credential operation.

## JWKS Mismatch

Symptoms:

- Backends reject valid-looking tokens.
- `credlease issuer show` does not match backend configuration.
- Exported JWKS is missing or stale.

Actions:

1. Re-export JWKS:

```bash
credlease jwks export --output <backend-jwks-path>
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

Credlease cannot revoke application-side writes that already happened with a valid leased token.
