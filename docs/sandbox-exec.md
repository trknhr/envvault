# External Sandbox Sessions

`envvault sandbox exec` launches a fresh process in an **existing** external
sandbox and connects selected EnvVault provider proxies. EnvVault owns access
policy, temporary capabilities, expiry, and revocation. The external runtime
owns containers, worktrees, terminal handling, and clipboard integration.

Unlike `sandbox run`, which creates and removes its own container, ending an
`exec` session never stops or removes the existing sandbox.

## Choose the command

| Command | Use it when | Sandbox owner |
| --- | --- | --- |
| `envvault sandbox exec` | Launch a tool in an existing agent-infra sandbox with selected API proxies. | agent-infra |
| [`envvault sandbox run`](/sandbox) | Create a container for one foreground command. | EnvVault |
| [`envvault sandbox plugin serve`](/sandbox-plugin) | Build a host-side controller that consumes EnvVault's connection protocol. | External platform |

You do not need to start `sandbox plugin serve` or run the standalone bridge
script before using `sandbox exec`.

## Requirements

The first adapter is experimental and supports macOS, a local Docker Desktop
`desktop-linux` context, and an existing running branch-only agent-infra
sandbox. Only HTTP provider-proxy `base-url` and `token` outputs are supported.

**Stock agent-infra 0.9.13 does not implement the required session interface.**
The initial extension is a separate local agent-infra source change based on
v0.9.13, not an upstream release. Build that modified checkout with `npm ci`
and `npm run build`, then select its `dist/bin/cli.js` with `--runtime-command`.
Cloning the unmodified tag is insufficient. EnvVault does not patch installed
npm packages or import their private modules.

### Build and check the local integration

Replace these paths with your EnvVault checkout and the **modified** agent-infra
checkout. Use the Go version required by EnvVault's `go.mod` and the Node/npm
versions required by the agent-infra checkout.

```bash
envvault_repo=/absolute/path/to/envvault
agent_infra_repo=/absolute/path/to/modified/agent-infra

(cd "$envvault_repo" && go build -o bin/envvault ./cmd/envvault)
(cd "$agent_infra_repo" && npm ci && npm run build)

export PATH="$envvault_repo/bin:$PATH"
envvault sandbox exec --help
"$agent_infra_repo/dist/bin/cli.js" sandbox session --help
```

Neither CLI is installed or replaced globally. The PATH change selects the
local EnvVault build for this shell; the examples below select the local
agent-infra executable explicitly. If either help command lacks the new
command, check the selected binary and source checkout before proceeding.

From the **host project that owns the sandbox**, check the existing target and
provider profiles:

```bash
cd /absolute/path/to/host/project
"$agent_infra_repo/dist/bin/cli.js" sandbox ls
envvault proxy list
```

Use a running branch listed by agent-infra as `--target`. Creation and startup
remain agent-infra operations; `sandbox exec` does not perform them.

## Launch

In the **host agent-infra project**, put references in `.env.sandbox` using an
existing profile from `envvault proxy list`. `gemini-openai/dev` is an example
profile name, not a profile that this command creates automatically:

```dotenv
TOOLS_API_URL=envvault://gemini-openai/dev/base-url
TOOLS_API_TOKEN=envvault://gemini-openai/dev/token
```

If you do not have a provider-proxy profile yet, configure one using the
[proxy workflow](/proxies) before launching the session.

```bash
envvault sandbox exec \
  --runtime agent-infra \
  --runtime-command "$agent_infra_repo/dist/bin/cli.js" \
  --target clipboard-test \
  --env-file .env.sandbox \
  -- codex
```

Omit `--runtime-command` once the `agent-infra` on PATH supports the session
contract. It accepts an executable path, not a shell expression. `agent-infra`
is currently the default and only external session runtime.

Interactive terminal and image paste are enabled by default. For a fresh shell
use `-- bash -i`, then run tools inside that shell. Existing tmux panes and
separately opened `docker exec` shells do not inherit this environment.
For scripts, add `--non-interactive` before `--`.

Repeat `--env-file` to overlay files in order. Repeat `--env NAME=envvault://...`
to override file values. Every profile needs both outputs; aliases are allowed.
Literal values, direct credentials, and host controls such as `PATH`,
`NODE_OPTIONS`, `DOCKER_HOST`, and `AGENT_INFRA_*` are rejected.

These variables give tools access to Gemini through the proxy. They do **not**
change Codex's model provider or native login configuration.

### Launch without an env file

The same references can be passed directly. Replace both occurrences of the
example profile name with your existing profile; do not substitute a real key:

```bash
envvault sandbox exec \
  --runtime agent-infra \
  --runtime-command "$agent_infra_repo/dist/bin/cli.js" \
  --target clipboard-test \
  --env TOOLS_API_URL=envvault://gemini-openai/dev/base-url \
  --env TOOLS_API_TOKEN=envvault://gemini-openai/dev/token \
  -- codex
```

`TOOLS_API_URL` and `TOOLS_API_TOKEN` are application variable names, not
special EnvVault settings. Configure the tool making the API request to use
both values. Send requests to the injected proxy URL, not directly to Google's
URL: the temporary token authenticates to EnvVault, not to the upstream API.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| EnvVault help has no `sandbox exec` command | Build this checkout and select its `bin/envvault`; an older installed binary may still be on PATH. |
| `ENVVAULT_RUNTIME_INCOMPATIBLE` | Check `--runtime-command`, session support, the running branch target, and local Docker Desktop. Stock agent-infra 0.9.13 is incompatible. |
| `ENVVAULT_PROFILE_NOT_FOUND` | Run `envvault proxy list` on the host. Replace the example profile in both references with an existing provider-proxy profile. |
| `ENVVAULT_PROJECT_NOT_TRUSTED` | Launch from the host project that owns the sandbox and check the profile's project binding. Do not disable trust checks to bypass a project mismatch. |
| `ENVVAULT_CONFIG_INVALID` | Supply `--target`, an explicit `-- command`, and both proxy outputs. Do not include literal values, raw credential references, or host-control variables. |
| Terminal required | Run from an interactive host terminal, or add `--non-interactive` before `--` for a script. Non-interactive mode disables clipboard integration. |
| Variables missing in another shell | Only the newly launched process and its children inherit them. Use `-- bash -i`; an existing tmux pane or separate `agent-infra sandbox exec` shell does not inherit the lease. |
| Session reports cancellation or expiry | Start a new EnvVault session. Leases are not renewed automatically. |

Image paste is handled by agent-infra's interactive session. This adapter does
not add MCP servers or forward OAuth browser callbacks; freee MCP authorization
must be configured separately.

## Lifecycle and security

1. Validate references without reading credentials.
2. Ask agent-infra to prepare and describe the sandbox.
3. Check its reported project against the host project and open a lease for
   the full container ID.
4. Ask agent-infra to revalidate that ID and launch the new process. Temporary
   values travel in the trusted runtime child's environment; arguments contain
   variable names, not token values. Only selected variables enter the container.
5. Revoke access on exit, failure, signal, or expiry. There is no automatic
   renewal; launch another session to obtain fresh access.

The connection is **brokered**, not `brokered-enforced`. This adapter does not
apply default-deny egress or remove native credentials/mounts already provided
by agent-infra. An intentionally detached process may outlive the launcher,
but its capability becomes unusable after revocation. The host runtime and
its executable are trusted components.

The gateway listens on an ephemeral host port at `0.0.0.0` and advertises
`host.docker.internal`. This broadens reachability: use a trusted host/network
and do not publish the gateway externally. All requests require a token.
Application output is not redacted; do not print environment values or enable
verbose request-header logs.

MCP/freee OAuth, original-URL outbound attachment, task-bound sandboxes, remote
Docker, tmux reattachment, and automatic creation are outside this first step.

## Versioned runtime interface

EnvVault invokes these host commands:

```bash
agent-infra sandbox session prepare \
  --protocol agent-infra.sandbox-session/v1 --target BRANCH --non-interactive
```

Successful stdout contains one credential-free JSON object, limited to 64 KiB:

```json
{
  "protocol": "agent-infra.sandbox-session/v1",
  "target": "BRANCH",
  "container_id": "FULL_64_CHARACTER_LOWERCASE_HEX_ID",
  "project_root": "/canonical/host/project",
  "git_remote": "",
  "engine": "docker-desktop"
}
```

After opening the lease, EnvVault invokes:

```bash
agent-infra sandbox session exec \
  --protocol agent-infra.sandbox-session/v1 \
  --target BRANCH --container-id FULL_ID \
  --env TOOLS_API_URL --env TOOLS_API_TOKEN --non-interactive -- COMMAND
```

Omit `--non-interactive` on both calls for terminal sessions. The runtime must
fail on a changed/missing/stopped container, incorrect project/branch labels,
unavailable clipboard session, or invalid environment names. It streams the
application output, preserves its exit status, and forwards cancellation to
its child. Capabilities must not be persisted in configuration, token files,
or container creation metadata.

EnvVault uses the existing broker in-process for this command. Platforms that
own the outer command can instead use [`sandbox plugin serve`](/sandbox-plugin)
to consume that broker over its provider protocol. No plugin manager is needed.

## Verify without provider credentials

From the EnvVault checkout:

```bash
cd "$envvault_repo"
go test ./internal/sandboxsession/... ./internal/cli
```

For a real Docker smoke test, the existing
`examples/agent-infra-bridge/testdata/mock-plugin` helper also accepts
`sandbox exec`. Build it to a temporary location and substitute it for
`envvault`; use `bridge-test/base-url` and `bridge-test/token`, then request
`GET /probe`. HTTP 200 with `{"ok":true}` confirms credential injection; an
invalid capability must receive HTTP 401. The helper uses an in-memory keyring
and loopback mock provider, never real profiles or provider credentials.
