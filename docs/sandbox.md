# Experimental Docker Sandbox

`envvault sandbox run` launches a foreground command in Docker and can deliver
short-lived provider-proxy capabilities without delivering the real upstream
credential. The command is experimental and currently reports `brokered`, not
`brokered-enforced`.

## Prerequisites

- Docker Desktop on macOS or a current Docker Engine on Linux.
- A container image containing the command to run.
- For brokered credentials, a stored credential and provider-proxy profile.
- For original-URL outbound attachment, a proxy-aware client supported by the
  current prototype.

Codex is a recognized agent. EnvVault configures an invocation-scoped custom
model provider for it, so a project `.env` file is not required. This first
slice supports both an API-key-backed `openai-compatible` proxy that allows
`POST /responses` and an explicitly selected, isolated native OAuth home. Host
Codex OAuth sessions are never inherited implicitly.

Create the proxy using the normal workflow:

```bash
envvault credential set app/dev

envvault proxy add api-proxy/dev \
  --credential app/dev \
  --provider generic \
  --target https://api.example.com \
  --allow-path /v1/messages \
  --allow-method POST
```

Keep only proxy output references in `.env`:

```dotenv
APP_BASE_URL=envvault://api-proxy/dev/base-url
APP_API_TOKEN=envvault://api-proxy/dev/token
```

## Run

```bash
envvault sandbox run \
  --runtime docker \
  --image node:22 \
  --env-file .env \
  -- npm test
```

EnvVault reports the sandbox ID and security level on stderr, streams container
stdout and stderr, and returns the container exit code:

```text
sandbox: sbx_...
security: brokered (experimental; direct egress is not blocked)
```

Agent authentication and application outbound credentials are separate
attachments:

| Need | Option | Credential material visible in the container |
| --- | --- | --- |
| Codex model access through an API-key proxy | automatic discovery or `--agent-auth <profile>` | Short-lived proxy capability; not the provider API key |
| Codex ChatGPT OAuth | `--agent-auth native --agent-auth-profile <name>` | Writable OAuth state in an isolated `CODEX_HOME` |
| APIs called by applications or tools inside Codex | repeatable `--outbound-profile <profile>` | Literal `envvault://<credential>` handle, proxy capability, and public CA; not the provider API key |

Selecting native Codex auth does not automatically attach Gemini, Kaggle, or
other application APIs. Attach only the outbound profiles needed by the
current workspace.

For an interactive terminal application such as a shell or Codex, keep stdin
open and allocate a pseudo-TTY with `-it`.

Build the example Codex image once. The narrow build context avoids sending the
project workspace to the Docker builder:

```bash
docker build \
  --tag envvault-codex:local \
  examples/codex-sandbox
```

The image pins Codex CLI by default. Override `CODEX_VERSION` with a build
argument when deliberately upgrading it.

### Codex with an API-key proxy

```bash
envvault credential set openai/dev

envvault proxy add openai-codex/dev \
  --credential openai/dev \
  --provider openai-compatible \
  --target https://api.openai.com/v1
```

When exactly one compatible profile exists, EnvVault attaches it
automatically:

```bash
envvault sandbox run -it \
  --runtime docker \
  --image envvault-codex:local \
  -- codex
```

With multiple compatible profiles, select one explicitly:

```bash
envvault sandbox run -it \
  --agent-auth openai-codex/dev \
  --runtime docker \
  --image envvault-codex:local \
  -- codex
```

Use `--no-agent-auth` to leave the Codex command and environment untouched.
Automatic recognition applies only when `codex` is invoked directly, not when
it is hidden inside `sh -lc` or another wrapper.

The sandbox receives `ENVVAULT_CODEX_TOKEN`, which is a short-lived gateway
capability, and invocation-only Codex provider overrides. It does not receive
the OpenAI credential or the host `~/.codex` directory. The adapter follows
Codex's documented custom provider `base_url` and `env_key` configuration:
<https://learn.chatgpt.com/docs/config-file/config-reference>.

### Codex with native ChatGPT OAuth

Native mode lets the official Codex CLI own browser/device login and token
refresh. EnvVault creates a private state directory for each agent/profile,
mounts it read-write at `CODEX_HOME`, and forces Codex credential storage to
`file`. It does not copy or mount the operator's normal `~/.codex` directory.

Login once using device authorization, which avoids depending on a localhost
OAuth callback inside the container:

```bash
envvault sandbox run -it \
  --agent-auth native \
  --agent-auth-profile personal \
  --runtime docker \
  --image envvault-codex:local \
  -- codex login --device-auth
```

Reuse the same isolated profile for subsequent sessions:

```bash
envvault sandbox run -it \
  --agent-auth native \
  --agent-auth-profile personal \
  --runtime docker \
  --image envvault-codex:local \
  -- codex
```

The profile defaults to `default` when `--agent-auth-profile` is omitted.
Profile names may contain letters, numbers, dots, dashes, and underscores. The
state is stored below EnvVault's private data directory at
`agent-auth/codex/<profile>`.

Codex documents that file-backed credentials live in `auth.json` below
`CODEX_HOME` and contain access tokens. Consequently, native mode reports
`materialized-static`: code in the container can read, copy, replace, or delete
the OAuth state, and refreshed state persists into the next invocation. Use a
dedicated profile per trust boundary. See
<https://learn.chatgpt.com/docs/auth#credential-storage>.

On Linux, the image user must have permission to write the host-backed state
directory. The example image uses the common UID 1000; images with a different
UID may require matching user configuration in a future runtime adapter.

Run `codex logout` through the same native profile to clear its active login.
`envvault reset` also removes all EnvVault-managed native agent auth profiles;
review `envvault reset --dry-run` before doing so.

### Original-URL outbound profiles

`--outbound-profile` keeps the provider URL unchanged. EnvVault starts one
host-side outbound broker, configures the Docker workload to use it, and
injects the profile credential only when scheme, destination, method, and path
match policy.

Create a normal bearer provider-proxy profile. In this example the trusted
base path is `/v1`, so allowed paths are relative to it:

```bash
envvault credential set tools-api/dev

envvault proxy add tools-api-outbound/dev \
  --credential tools-api/dev \
  --provider generic \
  --target https://api.example.com/v1 \
  --allow-path /messages \
  --allow-method POST
```

Keep the application's normal API-key variable in `.env`, but make its value
the exact underlying credential reference used by the profile:

```dotenv
TOOLS_API_KEY=envvault://tools-api/dev
```

If the application loads `/workspace/.env` itself, leave out `--env-file`; the
mounted project file is not rewritten. Use `--env-file .env` when the
application expects the same literal reference in its process environment.

Attach it independently of Codex's own model authentication:

```bash
envvault sandbox run -it \
  --agent-auth native \
  --agent-auth-profile personal \
  --outbound-profile tools-api-outbound/dev \
  --env-file .env \
  --runtime docker \
  --image envvault-codex:local \
  -- codex
```

A process launched by Codex can initialize its SDK with `TOOLS_API_KEY` and
request the original URL `https://api.example.com/v1/messages`; it does not
need an EnvVault base URL. The SDK sends the literal reference in its bearer
authentication field. After destination, method, and path checks, the broker
accepts only the exact credential reference declared by the attached profile
and replaces that field with the real credential. A missing reference, another
credential reference, or a raw value is rejected locally. The flag is
repeatable for distinct routes.

Use `envvault sandbox run --all` when a trusted local session needs every
provider-proxy profile available to the current workspace:

```bash
envvault sandbox run -it \
  --agent-auth native \
  --agent-auth-profile personal \
  --all \
  --runtime docker \
  --image envvault-codex:local \
  -- codex
```

`--all` expands profiles in stable name order and rechecks every project
binding. Profiles bound to another project and non-provider-proxy profiles are
not attached. Profiles with `project-binding none` are available in every
workspace and are therefore included. The command fails if no profiles are
available, if a selected credential is missing, or if selected routes conflict.
It cannot be combined with `--outbound-profile` and does not select Codex's
agent authentication. Because profiles added later are included automatically,
prefer explicit profile names for reproducible or less-trusted sessions.

The Docker adapter injects `HTTP_PROXY`, `HTTPS_PROXY`, lowercase equivalents,
`NODE_USE_ENV_PROXY=1`, and `NODE_EXTRA_CA_CERTS`. It mounts only an ephemeral
public CA certificate at `/etc/envvault-outbound/ca.pem`; the CA private key and
provider credential stay in the host process. The example image pins Node
22.22.2. Node versions before 22.21.0 do not provide the built-in environment
proxy behavior used by this Codex prototype.

If the invocation also uses EnvVault's base-URL gateway, its exact host and port
are added to `NO_PROXY` to avoid proxy recursion. User-supplied values for the
proxy and Node trust variables are rejected rather than silently overwritten.

The current profile translator supports late binding only in a bearer
authentication header. Gemini API-key headers, Kaggle-specific authentication,
signed requests, and agent OAuth adapters are follow-up provider adapters. See
[RFC 0003](./rfcs/0003-url-preserving-outbound-broker.md) for the trust model
and enforced-egress follow-up.

### Daily Codex wrapper (zsh)

For local interactive use, put this function in `~/.zshrc`. It attaches no
application outbound profile by default. Add selected profiles with repeatable
`-o` or `--outbound-profile`, or attach every profile available to the current
workspace with `--all`:

```zsh
evcodex() {
  local envvault_bin="${ENVVAULT_BIN:-envvault}"
  local agent_profile="${ENVVAULT_AGENT_AUTH_PROFILE:-personal}"
  local image="${ENVVAULT_CODEX_IMAGE:-envvault-codex:local}"
  local -a outbound_args

  while (( $# )); do
    case "$1" in
      -o|--outbound-profile)
        if (( $# < 2 )); then
          print -u2 "usage: evcodex [--all | -o PROFILE ...] [-- CODEX_ARGS...]"
          return 2
        fi
        outbound_args+=(--outbound-profile "$2")
        shift 2
        ;;
      --all)
        outbound_args+=(--all)
        shift
        ;;
      --)
        shift
        break
        ;;
      *)
        break
        ;;
    esac
  done

  command "$envvault_bin" sandbox run -it \
    --agent-auth native \
    --agent-auth-profile "$agent_profile" \
    "${outbound_args[@]}" \
    --runtime docker \
    --image "$image" \
    -- codex "$@"
}
```

Reload the shell, then choose profiles per invocation:

```bash
# Codex OAuth only; no application API profile is attached.
evcodex

# Make Gemini available to applications launched in this session.
evcodex -o gemini-openai/dev

# Attach multiple independent outbound routes.
evcodex -o gemini-openai/dev -o tools-api-outbound/dev

# Attach every provider-proxy profile allowed for this workspace.
evcodex --all

# Everything after -- is passed to Codex.
evcodex -o gemini-openai/dev -- --version
```

Use `envvault proxy list` to see available profile names. The current outbound
adapter supports bearer credentials; a service that uses another
authentication scheme needs a provider adapter before it can be attached this
way.

The wrapper-specific options must come first. `--all` and `-o` cannot be
combined. Use `--` when a Codex option could be confused with `-o`. Override
the wrapper's non-secret defaults when needed:

```bash
export ENVVAULT_BIN=/absolute/path/to/envvault/bin/envvault
export ENVVAULT_AGENT_AUTH_PROFILE=work
export ENVVAULT_CODEX_IMAGE=envvault-codex:local
```

Do not put credentials in those variables. The wrapper intentionally omits
`--env-file`: an application may load its mounted project `.env` itself. If an
application requires values in its process environment, use the full
`envvault sandbox run ... --env-file .env` command; matching outbound
credential references stay literal.

`-i` and `-t` are independent flags. Omit both for CI and other non-interactive
server commands.

The invocation directory is mounted read-write at `/workspace`. No host home,
OS credential store, or Docker socket is mounted. The root filesystem is
read-only, while `/tmp` and `/home/envvault` are tmpfs mounts. Native agent auth
adds only the selected EnvVault-managed state directory beneath that temporary
home.

Publish a web port on a random host-loopback port:

```bash
envvault sandbox run \
  --runtime docker \
  --image node:22 \
  --publish 3000 \
  -- npm run dev -- --host 0.0.0.0
```

EnvVault prints the mapped address after the container starts:

```text
app: http://127.0.0.1:49172 (container port 3000)
```

## Credential Delivery

Provider-proxy references are rewritten for the container:

- `envvault://<proxy>/base-url` becomes a container-reachable host gateway URL.
- `envvault://<proxy>/token` becomes a short-lived bearer capability.
- The upstream credential remains in the host credential store and gateway
  memory.

With `--outbound-profile`, the sandbox instead receives a capability-bearing
proxy URL and public CA. A direct reference for the profile's underlying
credential remains literal in the container, so the application can use its
normal environment-variable name, SDK initialization, and provider URL. The
host broker requires that exact reference in the configured bearer header and
replaces it only after policy checks. Credential references are non-secret; the
separate proxy capability is sensitive and remains usable until lease expiry or
cleanup.

Any direct reference not covered by an attached outbound profile fails before
a container is created:

```text
ENVVAULT_CONFIG_INVALID: direct credential references are not allowed unless attached to a matching outbound profile
```

For an explicit compatibility fallback:

```bash
envvault sandbox run \
  --runtime docker \
  --image node:22 \
  --allow-materialized-secrets \
  --env DATABASE_URL=envvault://database/dev \
  -- your-command
```

This reports `materialized-static`. The raw credential is then present in the
container environment and metadata.

## Docker Defaults

The experimental runtime uses these fixed defaults:

- bridge networking; host networking and privileged mode are not used;
- all Linux capabilities dropped and `no-new-privileges` enabled;
- read-only root filesystem;
- PID limit 256, memory limit 512 MiB, and CPU limit 1;
- the invocation workspace bind-mounted at `/workspace`; native agent auth also
  mounts its explicitly selected isolated state directory;
- ephemeral HOME and `/tmp` tmpfs mounts;
- published ports bound to random `127.0.0.1` ports;
- EnvVault labels and random container names for cleanup.

Running from the filesystem root or directly from the host home directory is
rejected. A workspace that contains a known Docker socket is also rejected.

## Platform Notes

On macOS, the runtime uses Docker Desktop's `host.docker.internal` route. On
Linux, it asks Docker Engine to map that name to `host-gateway`. Rootless Docker
and custom daemon/network configurations may not provide a usable route; the
sandbox then fails rather than falling back to host networking. Windows is not
supported by this experimental runtime.

These platform routes affect reachability only. Neither macOS nor Linux is
reported as `brokered-enforced` by this version.

## Security Boundary and Limitations

This version does not enforce egress policy. The application container can
connect directly to the internet and may reach other host services through the
Docker bridge. The host gateway temporarily listens on an ephemeral port that
is reachable by the container; access requires a random short-lived token and
is still constrained by the proxy method/path allowlist.

Outbound attachment is cooperative. A client that ignores `HTTP(S)_PROXY` can
bypass it through direct bridge egress. TLS pinning and clients that do not use
the mounted additive CA will fail for configured HTTPS destinations. The
trusted outbound broker terminates TLS and can observe allowed request headers
and bodies. Unconfigured public HTTP/HTTPS destinations pass through without
credential injection; unconfigured private, loopback, and link-local
destinations are rejected by the broker, but may remain directly reachable
from the container.

The gateway token is intentionally available in the container environment and
Docker metadata. It is a temporary capability, not the upstream credential.
Anyone who obtains it can use the gateway until expiry or sandbox cleanup.

Native auth has a wider credential boundary than brokered proxy mode. The
container receives writable OAuth state, including refresh material, and the
state deliberately survives sandbox cleanup. Direct bridge egress means a
malicious image or workspace command can exfiltrate it. Persistent agent config
can also be poisoned for later runs. Do not reuse one native profile across
unrelated trust domains.

Docker Engine and the host Docker daemon are trusted. Container escape, Docker
daemon compromise, malicious images, writes to the mounted workspace, direct
egress, DNS controls, metadata endpoints, and access to unrelated reachable
host services are not prevented by `brokered` mode.

Normal completion, start/wait failure, and Ctrl-C remove the container and
close the gateway. A host crash or forced EnvVault termination can leave a
labeled container. Inspect leftovers without deleting them:

```bash
docker ps -a --filter label=io.envvault.managed=true
```

Review the exact container ID before removing a leftover with `docker rm -f`.

## Development Verification

The real-Docker integration suite is opt-in because it starts containers and
uses the locally available `node:22-slim` image:

```bash
ENVVAULT_DOCKER_TEST=1 \
ENVVAULT_DOCKER_TEST_IMAGE=node:22-slim \
go test ./internal/providerproxy ./internal/sandbox/docker ./internal/cli -count=1
```

It verifies proxy allow/deny behavior, absence of the upstream credential from
the container environment, mounted writable areas, Docker metadata, and CLI
output, loopback-only random port publication, capability shutdown, normal
cleanup, interrupt cleanup, original-URL HTTP routing, and HTTPS interception
through the ephemeral CA. Tests use a fake marker credential, never a real
provider key.
