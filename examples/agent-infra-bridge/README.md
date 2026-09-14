# EnvVault → agent-infra bridge (experimental)

The native [`envvault sandbox exec`](../../docs/sandbox-exec.md) integration
uses a versioned agent-infra session command instead of private npm imports.
It requires the separate session-enabled agent-infra build. This standalone
prototype remains available for the stock 0.9.13 installation.

Use EnvVault HTTP provider proxies inside an **existing** agent-infra sandbox,
including agent-infra's macOS image clipboard bridge. The adapter runs on the
host and speaks `envvault.sandbox-plugin/v1`; upstream API keys remain in
EnvVault's host-side credential store and gateway.

This first adapter supports **macOS, Docker Desktop, agent-infra 0.9.13, and
running branch-only sandboxes**. It rejects other versions because it uses
version-specific agent-infra modules, not a stable upstream extension API.
Node 22.9+ is required. There are no additional npm dependencies to install.

## Launch

Make sure `envvault`, `agent-infra`, and Docker are on the host PATH. Your
EnvVault executable must support `envvault sandbox plugin serve`; to build
the version in this repository, run `go build -o ./bin/envvault ./cmd/envvault`
from the EnvVault repository root and pass its absolute path with `--envvault`.

In your **agent-infra project on the host**, first check that the sandbox is
running:

```bash
agent-infra sandbox ls
```

For an existing EnvVault provider-proxy profile named `tools-api/dev`, launch:

```bash
node /path/to/envvault/examples/agent-infra-bridge/bridge.mjs clipboard-test \
  --env TOOLS_API_URL=envvault://tools-api/dev/base-url \
  --env TOOLS_API_TOKEN=envvault://tools-api/dev/token
```

Replace `/path/to/envvault`, the branch, and the profile name with your values.
Use `--agent-infra /absolute/path/to/agent-infra` or
`--envvault /absolute/path/to/envvault` if needed.

This opens a **fresh bash shell**, not the existing tmux session. Commands
launched from this shell inherit the temporary API URL and bearer capability:

```bash
codex
```

Or launch the agent directly, still with the clipboard bridge:

```bash
node /path/to/envvault/examples/agent-infra-bridge/bridge.mjs clipboard-test \
  --env TOOLS_API_URL=envvault://tools-api/dev/base-url \
  --env TOOLS_API_TOKEN=envvault://tools-api/dev/token \
  -- codex
```

This does **not** change Codex's model provider or login configuration. The
`TOOLS_API_*` variables are for your tools/application. If using EnvVault for
model-provider authentication, configure the client to use that proxy's base
URL and temporary token as a separate step. Native auth/config mounts already
created by agent-infra are preserved, not removed or made secretless.

Copy an image on macOS, focus the running agent, and press **Control–V**.
The adapter calls agent-infra's image-paste PTY even for an explicit command.
It fails closed if the clipboard bridge is unavailable; it does not silently
fall back to a terminal without the injected connection values.

For scripts without a terminal, specify both `--non-interactive` and a command:

```bash
node /path/to/envvault/examples/agent-infra-bridge/bridge.mjs clipboard-test \
  --env TOOLS_API_URL=envvault://tools-api/dev/base-url \
  --env TOOLS_API_TOKEN=envvault://tools-api/dev/token \
  --non-interactive -- node -e '
    const r = await fetch(process.env.TOOLS_API_URL + "/health", {
      headers: { Authorization: "Bearer " + process.env.TOOLS_API_TOKEN }
    });
    console.log("HTTP", r.status);
    if (!r.ok) process.exitCode = 1;
  '
```

Use a route/method permitted by your profile. Every profile needs both
`base-url` and `token` outputs. Repeat `--env` for multiple profiles or aliases.
Raw values, direct credential references, duplicate names, and host execution
controls such as `PATH`, `HOME`, and `DOCKER_HOST` are rejected. Output names
must be uppercase application variable names. Project-bound profiles are
checked against the host agent-infra repository root and its origin remote.

## Lifetime and security

- Readiness checks and branch/label validation happen before opening a lease.
  The lease and Docker exec use the full container ID, not its reusable name.
- The host plugin's stdin/stdout remain private. Only selected URL/token
  outputs enter the new container process via name-only `docker exec --env`
  options. The bridge does not write token files, edit `.airc.json`, rebuild
  images, install packages, or change persistent container environment.
- The bridge suppresses plugin diagnostics that could contain capabilities.
  The interactive application's output is not redacted: do not run `env`,
  `printenv`, or commands that intentionally display credentials.
- Normal command exit, bridge signals, lease expiry, and plugin failure close
  access. There is no automatic renewal. Existing tmux sessions are not given
  new credentials. A deliberately detached process may outlive the bridge,
  but its capability no longer works after the lease closes.
- The container is not stopped or deleted when the bridge exits. Its native
  credentials, mounts, other processes, and non-EnvVault access are unchanged.
- The advertised gateway uses `host.docker.internal` and an ephemeral host
  listener on `0.0.0.0`. This broadens listener reachability; use a trusted
  local host/network and do not publish the gateway externally.
- Security is **brokered**, not `brokered-enforced`: this adapter does not
  apply default-deny egress or prevent bypass via other credentials already
  present in the sandbox. Provider path/method policy applies at the gateway.
- MCP/freee OAuth, native credential isolation, task-bound sandboxes, remote
  Docker, other runtimes, automatic sandbox creation, and tmux reattachment
  are outside this first step.

See [the plugin contract](../../docs/sandbox-plugin.md). The only version-bound
integration is in `runtime.mjs`; a future public agent-infra hook can replace
it without changing the EnvVault protocol or lease lifecycle.

## Tests without real credentials

From the EnvVault repository root:

```bash
node --test examples/agent-infra-bridge/test/*.test.mjs
```

To also exercise the real Go broker, build the test-only in-memory provider:

```bash
bridge_test_dir=$(mktemp -d /tmp/envvault-bridge-test.XXXXXX)
go build -o "$bridge_test_dir/mock-plugin" \
  ./examples/agent-infra-bridge/testdata/mock-plugin
ENVVAULT_BRIDGE_TEST_PLUGIN="$bridge_test_dir/mock-plugin" \
  node --test examples/agent-infra-bridge/test/*.test.mjs
```

The fixture uses a synthetic credential and a local mock upstream. It does
not read or write the OS keyring, EnvVault configuration, or a real provider.
The integration test checks upstream credential injection, missing/invalid
authorization, path policy, and revocation after session exit.

For a Docker/clipboard smoke test, run the adapter from the trial repository
with `--envvault "$bridge_test_dir/mock-plugin"`, map the profile `bridge-test`,
and request `/probe` using GET. A successful request returns `{"ok":true}`.
The test lease lasts one minute. The fixture is not for real credentials.

The tests cover protocol framing, response bounds, invalid leases, output
validation, capability-free argv, exit codes, cancellation, expiry, and plugin
failure. Actual macOS clipboard interaction needs a manual Control–V test.
