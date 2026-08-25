# RFC 0002: External sandbox plugin contract

- Status: Implemented experimentally
- Date: 2026-08-07
- Task: EVS-006

## Summary

EnvVault integrates with an existing agent sandbox as a trusted connection
provider. The sandbox platform continues to own runtime creation, workspace and
process isolation, network enforcement, and agent lifecycle. EnvVault owns
credential resolution, short-lived connection leases, protocol-aware gateways,
and revocation.

The first integration boundary is a versioned newline-delimited JSON protocol
over a child process's stdin and stdout:

```bash
envvault sandbox plugin serve
```

This process boundary is language-neutral, avoids a Go plugin ABI, and does not
require a separately authenticated daemon for the local MVP. The controlling
platform must keep stdin open while any lease is active. Closing stdin, stopping
the process, or sending `close` revokes the associated gateway capabilities.

## Product ownership

| Concern | Owner |
| --- | --- |
| Container, VM, or pod lifecycle | Agent sandbox |
| Filesystem and process policy | Agent sandbox |
| Default-deny egress | Agent sandbox |
| `envvault://` profile and keyring lookup | EnvVault |
| Provider method/path policy | EnvVault connection adapter |
| Raw upstream credential | EnvVault credential provider and trusted gateway |
| Temporary capability delivery | EnvVault plugin protocol |
| Lease teardown | Sandbox lifecycle calling EnvVault `close` |

`envvault sandbox run` remains a reference runtime and integration harness. It
is not the required entry point for an agent sandbox that implements this
contract.

## Trust boundary

The plugin process and the platform process controlling its stdin and stdout
are trusted. The plugin protocol must never be exposed inside the untrusted
sandbox. In particular, the sandbox must not receive:

- the plugin process stdin or stdout handles;
- EnvVault's keyring access;
- a control or management endpoint; or
- an upstream credential.

An `open` response intentionally contains a short-lived gateway capability.
That response is sensitive operational data: the control plane may inject the
selected values into the sandbox but must not log the response or persist it in
sandbox metadata longer than necessary.

The plugin emits protocol responses only on stdout. Fatal process-level errors
may be written to stderr, but neither stream may contain the upstream
credential. Request errors use stable EnvVault error codes and redacted
messages.

## Protocol

The current protocol identifier is:

```text
envvault.sandbox-plugin/v1
```

Each line contains exactly one JSON object. Unknown fields and messages larger
than 256 KiB are rejected. Request IDs and sandbox IDs are bounded opaque
identifiers.

### Ping

```json
{"protocol":"envvault.sandbox-plugin/v1","id":"health-1","method":"ping"}
```

```json
{"protocol":"envvault.sandbox-plugin/v1","id":"health-1","ok":true,"status":"ready"}
```

### Describe

`describe` returns repository-safe provider metadata that a sandbox adapter can
translate into its native provider catalog and policy model. It includes the
destination, protocol, HTTP method/path rules, available output parts, and TTL.
It omits the EnvVault credential reference and value.

```json
{
  "protocol": "envvault.sandbox-plugin/v1",
  "id": "describe-1",
  "method": "describe",
  "describe": {"profiles": ["openai-codex/dev"]}
}
```

Project identity may be included in `describe` just as it is in `open`; a
project-bound profile fails closed when the identity does not match.

### Open

The control plane chooses the environment-variable names expected by the
agent. Only provider-proxy `base-url` and `token` outputs are supported. Direct
credential materialization is not part of this protocol.

```json
{
  "protocol": "envvault.sandbox-plugin/v1",
  "id": "open-1",
  "method": "open",
  "open": {
    "sandbox_id": "openshell-sbx-123",
    "project": {
      "root": "/absolute/project/root",
      "git_remote": "git@github.com:example/project.git"
    },
    "bindings": [
      {
        "profile": "openai-codex/dev",
        "outputs": [
          {"environment": "OPENAI_BASE_URL", "part": "base-url"},
          {"environment": "OPENAI_API_KEY", "part": "token"}
        ]
      }
    ]
  }
}
```

The response contains values that may be delivered to the sandbox and the
gateway endpoints that the sandbox network policy must make reachable:

```json
{
  "protocol": "envvault.sandbox-plugin/v1",
  "id": "open-1",
  "ok": true,
  "lease": {
    "lease_id": "plugin_...",
    "sandbox_id": "openshell-sbx-123",
    "security_level": "brokered",
    "expires_at": "2026-08-07T12:30:00Z",
    "environment": {
      "OPENAI_BASE_URL": "http://host.docker.internal:49152/openai-codex/dev",
      "OPENAI_API_KEY": "<short-lived-capability>"
    },
    "egress": [
      {"network": "tcp", "address": "host.docker.internal:49152"}
    ],
    "connections": [
      {
        "profile": "openai-codex/dev",
        "gateway": {"network": "tcp", "address": "host.docker.internal:49152"},
        "expires_at": "2026-08-07T12:30:00Z"
      }
    ]
  }
}
```

The `egress` field describes EnvVault data-plane reachability. It is not an
instruction to allow the upstream provider directly.

### Close

```json
{
  "protocol": "envvault.sandbox-plugin/v1",
  "id": "close-1",
  "method": "close",
  "close": {"lease_id": "plugin_..."}
}
```

`close` is idempotent. The broker closes a lease automatically at its earliest
connection expiry. EOF revokes every outstanding lease, including leases for
which the control plane did not send `close`.

## Gateway placement

The default listener is `127.0.0.1:0`. A container-based integration that uses
a host route can launch the plugin as follows:

```bash
envvault sandbox plugin serve \
  --gateway-listen 0.0.0.0:0 \
  --gateway-host host.docker.internal
```

The listen port must be zero so every lease gets an ephemeral port. Listeners
are restricted to loopback, private, link-local, or unspecified addresses. An
unspecified listener requires an explicit advertised host.

The temporary bearer capability protects the data plane, but binding an
unspecified address increases reachability. The sandbox platform must restrict
network access to the returned endpoints and must not expose those ports
outside the trusted host.

## Security level composition

The v1 plugin reports `brokered`. EnvVault can prove that it did not deliver
the upstream credential, but it cannot prove that an external sandbox applied
the returned egress rules. A future runtime-specific adapter may compose this
lease with demonstrated default-deny enforcement and report
`brokered-enforced` at the platform layer. EnvVault's generic plugin does not
upgrade that claim itself.

## OpenShell mapping

An OpenShell adapter should:

1. launch one EnvVault plugin process from the trusted gateway/control plane;
2. use `describe` to map EnvVault policy into an OpenShell provider profile;
3. map an attached provider to EnvVault output aliases;
4. send `open` with the real OpenShell sandbox identity;
5. inject only the returned environment values into the sandbox;
6. allow only the returned EnvVault data-plane endpoints in the effective
   egress policy; and
7. send `close` when the sandbox or provider attachment is removed.

The first adapter may wrap this stdio contract from an OpenShell gateway
interceptor or companion service. A future native credential-source driver can
remove the wrapper without changing EnvVault's broker lifecycle.

## Failure behavior

- Invalid profiles, output mappings, project bindings, or protocol versions
  fail before a lease is returned.
- A partial multi-profile open closes every gateway already started for that
  request.
- Only one active plugin lease is allowed for one sandbox ID in one broker
  process.
- Lease IDs and capabilities are random and independent.
- The earliest connection expiry closes the complete multi-profile lease.
- Process EOF and context cancellation perform bounded best-effort cleanup.
- The upstream credential is never serialized into a protocol response.

## Scope and follow-ups

EVS-006 implements the local HTTP provider-proxy contract and stdio transport.
It does not implement an OpenShell package, remote tunneling, a public network
control API, PostgreSQL, or a generic TCP credential injector.

The next slice is an OpenShell adapter spike using a local gateway. Remote
sandboxes require a separately designed authenticated tunnel or co-located
credential provider and remain out of scope.
