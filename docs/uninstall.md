# Uninstall

Uninstall removes Credlease-owned local state. It must not delete repository files.

## Preferred Reset

Preview removal:

```bash
credlease reset --dry-run
```

Remove Credlease config, data, cache, JWKS, SQLite, and known OS credential store entries:

```bash
credlease reset --yes
```

## Manual Cleanup

Use this only if `credlease reset` is unavailable.

1. Remove Credlease config, data, and cache directories for the current OS user.
2. Delete OS credential store entries with these account names:

```text
credlease/talos/hmac/current
credlease/talos/signing/current
credlease/profile/<profile-name>/parent-key
```

3. Remove exported JWKS copies that you configured for local backends.
4. Remove `credlease://` references from project `.env` files if those projects no longer use Credlease.

Do not remove repository files as part of Credlease cleanup unless you intentionally own that project change.

## Verification

Run:

```bash
credlease doctor
```

After uninstall, missing config, SQLite, JWKS, and keyring entries are expected.
