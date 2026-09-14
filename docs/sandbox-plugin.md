# External Sandbox Plugin

`envvault sandbox plugin serve` lets an existing agent-sandbox control plane
use EnvVault as a connection provider. EnvVault does not create the sandbox.
It returns a temporary provider gateway URL and capability while the upstream
credential remains in the OS credential store and trusted EnvVault gateway.

This interface is experimental and currently supports HTTP provider-proxy
profiles.

For an EnvVault-owned launch command, see
[`envvault sandbox exec`](/sandbox-exec). It uses the same broker in-process
and delegates execution to a versioned external runtime interface. You do not
need to start this plugin process separately when using that command.

For the earlier standalone controller prototype, see the
[agent-infra bridge](/agent-infra-bridge). It delivers temporary API outputs
to an existing Docker Desktop sandbox while retaining macOS image paste, but
depends on stock agent-infra 0.9.13 private modules. The native `sandbox exec`
adapter uses the versioned session contract instead.

## Start the plugin

For a host process that can reach loopback:

```bash
envvault sandbox plugin serve
```

For a local container sandbox with a trusted host route:

```bash
envvault sandbox plugin serve \
  --gateway-listen 0.0.0.0:0 \
  --gateway-host host.docker.internal
```

The command speaks newline-delimited JSON on stdin and stdout. A controller
must keep the process stdin open for the complete sandbox lifetime. Piping one
request and immediately reaching EOF is useful for `ping`, but an `open` lease
would be revoked before a sandbox could use it.

## Protocol flow

Check readiness:

```json
{"protocol":"envvault.sandbox-plugin/v1","id":"health-1","method":"ping"}
```

Describe secret-free provider policy before creating a sandbox:

```json
{
  "protocol": "envvault.sandbox-plugin/v1",
  "id": "describe-1",
  "method": "describe",
  "describe": {"profiles": ["openai-codex/dev"]}
}
```

The response includes destination, protocol, HTTP method/path policy, available
output parts, and TTL. It does not include the credential reference or value.

Open a provider connection for a sandbox:

```json
{
  "protocol": "envvault.sandbox-plugin/v1",
  "id": "open-1",
  "method": "open",
  "open": {
    "sandbox_id": "agent-sandbox-123",
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

The successful response contains:

- `environment`: values to inject into the sandbox;
- `egress`: only the EnvVault gateway endpoints the sandbox must reach;
- `lease_id`: the handle to close during sandbox teardown;
- `expires_at`: the earliest connection expiry; and
- `security_level`: currently always `brokered`.

The environment contains a short-lived capability, not the upstream provider
key. Treat the complete response as sensitive and do not log it.

Close the lease:

```json
{
  "protocol": "envvault.sandbox-plugin/v1",
  "id": "close-1",
  "method": "close",
  "close": {"lease_id": "plugin_..."}
}
```

`close` is idempotent. The earliest connection expiry, EOF, or plugin
termination closes the complete lease.

## Integration boundary

The plugin process belongs in the sandbox platform's trusted control plane.
Never pass its stdin/stdout handles, OS keyring access, or a management socket
into the agent sandbox.

The sandbox platform remains responsible for:

- process, filesystem, and workspace isolation;
- applying default-deny network policy;
- allowing only the returned EnvVault gateway endpoints;
- preventing direct access to the upstream provider; and
- closing the lease on every teardown path.

EnvVault's generic plugin reports `brokered` because it cannot verify that an
external platform applied those network rules. See
[RFC 0002](/rfcs/0002-external-sandbox-plugin) for the complete wire contract,
trust model, failure behavior, and OpenShell mapping.
