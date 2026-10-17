# Export and Import

EnvVault stores credential values in the OS credential store on the machine
where they were registered. On macOS that store is the local login keychain,
written with `security add-generic-password`. iCloud Keychain does not sync
those items, so a second Mac signed into the same Apple ID starts empty.

`export` and `import` move credential values and profile configuration through
one encrypted file.

## Export

```bash
envvault export secrets.envault
```

EnvVault prompts for a passphrase twice, with echo disabled. The file is
replaced atomically and written with mode `0600`.

For a script, read one passphrase line from stdin. The flag does not take the
passphrase as its value:

```bash
envvault export secrets.envault --passphrase-stdin < /path/to/passphrase
```

Prefer the prompt. A passphrase typed into a shell pipeline can be saved in
shell history.

The file contains:

- credential values named in the config, including credentials referenced by
  profiles
- profile configuration for every stored profile

It does not contain:

- the installation id, defaults, or Talos runtime settings
- Talos HMAC or signing keys
- profile parent keys

Direct credentials and `inject` or `provider-proxy` profiles can be used on the
destination after import. `process` and `browser-session` profiles are copied
as policy, but leased-token issuance still needs parent keys created on that
machine. Project-binding path hashes and git roots are copied too. A path hash
belongs to the source checkout and may not match the other machine, so a bound
profile stays fail-closed until it is approved there.

Export fails when a named credential is missing or empty, or when there is
nothing to export.

## Import

Initialize the destination once, then import:

```bash
envvault init
envvault import secrets.envault
```

The passphrase is prompted once, again without echo. `--passphrase-stdin` reads
one line. Names that already exist are skipped, and the command still exits
successfully. The summary lists imported, replaced, and skipped names. It does
not print secret values.

Replace existing credential values and profile records explicitly:

```bash
envvault import secrets.envault --overwrite
```

A wrong passphrase and a file whose ciphertext was modified produce different
errors. Header fields are covered by the same key, so a modified header is
reported with the wrong-passphrase error. An unsupported version or a malformed
file is rejected before any credential is written. If saving the destination
config fails, credential-store changes from that import are rolled back.

## File Format

The file is versioned JSON. The version and KDF parameters are readable without
the passphrase; the credential payload is not.

```json
{
  "envvault_export": 1,
  "kdf": {
    "name": "argon2id",
    "time": 3,
    "memory": 65536,
    "threads": 4,
    "salt": "<base64>"
  },
  "aead": "aes-256-gcm",
  "nonce": "<base64>",
  "verifier": "<base64>",
  "ciphertext": "<base64>"
}
```

`memory` is KiB. Import uses the parameters stored in the file and rejects
values outside a bounded range. The passphrase is stretched with Argon2id to a
32-byte key. `verifier` is HMAC-SHA256 over the canonical header. `ciphertext`
is AES-256-GCM, with the header and verifier as additional data. The decrypted
payload is versioned JSON containing credential names, raw credential bytes,
and profile YAML.

Keep the passphrase out of the file name, shell history, and chat. Someone who
has both the file and the passphrase can read every exported credential.
