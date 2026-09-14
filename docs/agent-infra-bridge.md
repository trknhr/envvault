# agent-infra Bridge Prototype

For the native `envvault sandbox exec` command and versioned runtime interface,
see [External Sandbox Sessions](/sandbox-exec). The standalone example below
remains a prototype for stock agent-infra 0.9.13 and uses its private modules.
Use the native command for the new integration when you have the locally
modified, session-capable runtime; it does not invoke this script.

The experimental
[agent-infra bridge example](https://github.com/trknhr/envvault/tree/main/examples/agent-infra-bridge)
attaches EnvVault provider/API proxies to an existing agent-infra sandbox.
It preserves agent-infra's image clipboard bridge and leaves native agent
login/configuration unchanged.

The first adapter supports macOS, Docker Desktop, Node 22.9+, agent-infra
**0.9.13**, and already-running branch-only sandboxes. It uses version-specific
agent-infra modules and refuses other versions rather than guessing their API.

## Run from the host project

With an existing `tools-api/dev` EnvVault provider proxy:

```bash
node /path/to/envvault/examples/agent-infra-bridge/bridge.mjs clipboard-test \
  --env TOOLS_API_URL=envvault://tools-api/dev/base-url \
  --env TOOLS_API_TOKEN=envvault://tools-api/dev/token
```

Replace the repository path, branch and profile. This opens a fresh shell
whose child commands inherit temporary proxy outputs. Run `codex` from that
shell, or append `-- codex` to launch it directly with image paste. To script
a command without a terminal, use `--non-interactive -- <command>`.

The host adapter uses the [sandbox plugin](/sandbox-plugin) to open a lease
bound to the container ID. Values are passed through the Docker client's
environment, not command arguments or token files. The upstream key stays
in the trusted host gateway. Exiting the command closes the lease; interruption,
expiry and plugin failure also revoke access. Existing containers and tmux
sessions are not destroyed, and leases are not automatically renewed.

## Boundaries

The adapter reports `brokered`: it does not enforce default-deny egress.
It binds an ephemeral gateway on host `0.0.0.0`, advertised as
`host.docker.internal`; do not expose it outside the trusted host/network.
Existing agent-infra native credentials and mounts are unchanged, so this is
not a claim that the entire sandbox is secretless.

Both `base-url` and `token` outputs are required for each profile. Raw
credentials and host-control variables are rejected. Profile project bindings
use the host agent-infra repository identity. MCP/freee OAuth, model-provider
configuration, other engines, task-bound sandboxes and tmux reattachment are
not implemented by this first adapter.

See the
[example README](https://github.com/trknhr/envvault/blob/main/examples/agent-infra-bridge/README.md)
for installation checks, multiple-profile mappings, security details, and
tests using a mock provider without real credentials.

## Move to the native command

Keep the same running sandbox, provider profiles, and `--env` references.
Build the modified agent-infra checkout and EnvVault as described in
[External Sandbox Sessions](/sandbox-exec#build-and-check-the-local-integration),
then replace the `node .../bridge.mjs BRANCH` invocation with
`envvault sandbox exec --runtime agent-infra --target BRANCH`. Select the
modified runtime with `--runtime-command` and always append an explicit
command: `-- codex` or `-- bash -i`.

The prototype defaults to a shell; the native command requires `-- command`.
Neither path changes Codex's model provider or native login configuration.
