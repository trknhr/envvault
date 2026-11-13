# Codex in Microsandbox

With an EnvVault build containing `sandbox codex` (unreleased; not in v0.7.0),
install the optional native helper directly through the CLI:

```sh
envvault sandbox setup
```

For releases, setup downloads the helper from the same EnvVault release and
verifies its SHA-256 checksum. No repository checkout, Go compiler, or helper
PATH entry is needed. The CLI stores verified helpers under its private data
directory (`~/Library/Application Support/envvault/microsandbox` on macOS).
Apple Silicon macOS and amd64/arm64 Linux are supported. Intel macOS and Windows
are not supported by this launcher.

Setup is optional: the first launch installs a missing helper automatically.
After upgrading EnvVault, launch again or rerun setup to obtain the matching
helper. `envvault sandbox setup --force` downloads that version again for repair.
Existing policy and project data are reused; setup does not restart an active VM.

Then launch from any project directory:

```sh
cd /path/to/your/project
envvault sandbox codex
```

Your current directory is mounted read/write at `/workspace`, and Codex arguments
are forwarded unchanged:

```sh
envvault sandbox codex 'Explain this project without changing files.'
envvault sandbox codex --version
```

Run `envvault sandbox codex` in several terminals to run agents in parallel.
Terminals in the same workspace attach to one managed VM and share that project's
Codex history, sign-in, configuration, and caches. Different workspaces have
separate writable state. No storage names or paths need to be chosen.

Codex guides you through device login when a project needs authentication.
Parallel terminals reuse that project's sign-in. Host-managed EnvVault
credentials and live host policy apply to all sessions, with each selected
workspace's saved destination rules.

Agents in the same project share the VM's CPU, RAM, and process limit as well as
the workspace files. Use separate worktrees for independent edits and VM
isolation. The project boundary is the exact canonical directory mounted at
`/workspace`; symlink aliases reuse the same project, while other directories and
worktrees get separate state.

Resume from that same workspace with ordinary Codex arguments:

```sh
envvault sandbox codex resume
envvault sandbox codex resume --last
envvault sandbox codex resume <conversation-id>
```

History is available across parallel terminals and after a VM restart. A small
host supervisor owns the VM, credential proxy, and live policy controllers, so
closing one terminal leaves the others running. Shortly after the last terminal
exits, the supervisor stops and removes the VM while retaining project data.
On a later launch it starts a fresh VM with that project's state. A lost
supervisor cancels connected terminals; the next launch destroys any orphaned
project VM before reattaching its disk.

The earlier trial's global and pooled homes remain intact, and its already
running VMs are left alone. They are not automatically adopted by a project:
their contents have no reliable workspace association, so copying or reusing
them would expose another project's configuration or credentials. Existing trial
data needs an explicit migration; new project state starts separately.

For source development, build both binaries with:

```sh
./examples/microsandbox/install
export PATH="$HOME/.local/bin:$PATH"
```

This installs a development CLI into `~/.local/bin` (override with
`ENVVAULT_BIN_DIR`) and uses `envvault sandbox setup --helper <built-binary>` to
install the helper in managed storage. It leaves Homebrew's CLI installed
separately. Once Homebrew includes this command, remove the local
`~/.local/bin/envvault` binary to select Homebrew again. Development builds do
not fetch an arbitrary release helper. A legacy development helper on PATH is
used only when no managed helper exists.

When using a separately installed development helper, inspect rules or open a
shell from the same directory:

```sh
envvault-microsandbox rules
envvault-microsandbox shell
```

The helper also accepts an explicit host workspace before `--`:

```sh
envvault-microsandbox codex --workspace /path/to/project -- --version
```

For development without installation, the source wrapper captures the caller's
directory before changing to the Go module directory:

```sh
/path/to/envvault/examples/microsandbox/agent codex
```

The first launch builds and imports the Codex image, then starts a Linux VM. If
the dedicated home has no login, it runs device authentication: open the printed
URL in your Mac browser and enter its code. Codex starts when login completes.
Device login may need enabling in your ChatGPT settings or workspace permissions;
see the [official login guide](https://learn.chatgpt.com/docs/auth#login-on-headless-devices).

This is a custom experimental launcher. Docker prepares the OCI image;
Microsandbox runs that image in a Linux microVM. Subsequent launches use the
cached image. Docker is required for initial image preparation and rebuilds.

```sh
./agent login          # Explicitly run device login
./agent shell          # Shell with the same mounts and network controls
./agent rules          # Show the active host policy and mount details
./agent agent-check    # Verify live rules, process limits, and EnvVault injection
./agent agent-setup    # Rebuild and re-import the prepared image
```

After installing the updated CLI, run the optional live session regression:

```sh
python3 examples/microsandbox/check-sessions.py
```

It checks project isolation, parallel terminal lifetimes, the interactive resume
picker, `--last`, conversation IDs, history after VM restart, and recovery after
an unexpected supervisor exit. It uses fresh
temporary projects and an offline model-provider fixture, makes no model API
calls, and removes its own test volumes and metadata. Existing sandboxes and
policy are left intact. `go test -race ./...` in this example module exercises
the host proxy, workspace identity, and supervisor protocol without booting a VM.

The prepared image includes Codex 0.166.0, Go 1.27.3, Node.js 24.22.1, Git,
GitHub CLI 2.102.0, curl, ripgrep, and C/C++ build tools. GitHub CLI uses official
release binaries with pinned SHA-256 checksums. `./agent codex --version` checks Codex
without entering login. To start a simple first session:

```sh
./agent codex 'Explain this repository without changing files.'
```

The selected project directory is mounted in full at `/workspace`, **read/write**.
Edits affect the host project immediately, including dotfiles. The normal Mac home and Codex
configuration are not mounted. EnvVault manages persistent `/home/agent` storage,
including Codex login and caches, and isolates it between projects.
VM root-disk changes are discarded when the session exits; the shared repository
and persistent session data remain. Storage allocation and locking are automatic.
Codex authentication is readable inside the VM. Native agent login is separate
from the host-held application credentials described below.

The installed helper embeds its policy defaults and image build files. It does
not load launcher code or build files from the mounted project. The CLI rejects
a helper located inside that workspace, including symlinks into it. Host state
and EnvVault configuration must also stay outside the workspace. Saved credential
profiles are checked against the selected project's workspace binding.

The development `./agent` wrapper compiles host Go code from the source checkout.
Review launcher and dependency changes before rerunning that source wrapper.

Codex runs with `--sandbox danger-full-access --ask-for-approval on-request`
inside the VM. The microVM and host proxy enforce the outer boundary. The
launcher does not depend on Codex's nested Linux sandbox working on shared mounts.
The agent runs as UID/GID 1000 with no Linux capabilities and `no_new_privs`.
It cannot become root or change the host-controlled process limit.

## Live host network rules

The first launch copies `agent-policy.json` into the runtime home. The active
file defaults to `~/.envvault-msb-trial/agent-policy.json`; `./agent rules` prints
its exact location. It is outside both guest mounts, so the guest cannot edit
the active host rules.

Edit that **host file** to change `https_hosts`, for example by adding
`"example.com"`. Saving a valid policy takes effect on subsequent HTTPS
requests, without restarting the VM or agent. Removing a host also closes its
existing connections, including streams and upgrades, on the host proxy's
250 ms polling cycle, subject to scheduling. Invalid/unreadable policy blocks
new requests and closes existing connections; restoring valid JSON recovers.

The defaults permit HTTPS on port 443 to:

```text
auth.openai.com
chatgpt.com
api.openai.com
registry.npmjs.org
proxy.golang.org
sum.golang.org
storage.googleapis.com
```

Microsandbox's VM network policy permits gateway DNS and the local proxy port.
Direct internet traffic cannot bypass the proxy. The proxy terminates guest TLS
and verifies upstream TLS, checks each HTTPS request's hostname, and rejects
private/loopback/metadata upstream addresses. Only its public CA certificate is
installed in the guest; the CA private key stays in host memory. Header values
and bodies are not logged. The host allowlist applies to all guest processes.
Gateway DNS lookups remain available independently of that HTTPS allowlist.

By default, EnvVault references are discovered automatically, and saved proxy
profiles authorize each credential's host, methods, and paths. The sandbox
network allowlist also applies. CPU, memory, and mount changes still require a
fresh launch. The policy and proxy in this launcher are custom, rather than
Microsandbox's default network configuration.

## Live process limit

Set `"max_processes": 512` in the same host policy. The default is 512; valid
values are 16–8192. The count includes **threads**, as defined by Linux's
[cgroup PID controller](https://docs.kernel.org/admin-guide/cgroup-v2.html#pid).

The launcher places the agent and all descendants in a root-owned cgroup before
dropping privileges. The kernel denies new forks and threads at the limit.
Changing the number applies on the 250 ms polling cycle without restarting.
Lowering it below the current count leaves existing tasks running and blocks
new ones until the count drops or the host raises the limit. This is a count
limit; it does not restrict which executable names the agent can run.

Invalid/unreadable policy sets the agent cgroup limit to zero and blocks new
network requests. Restoring valid JSON recovers both controls. Host management
runs outside the agent cgroup, so it can raise an exhausted limit. If a limit
update cannot be applied and verified, the launcher stops the session.

## EnvVault credentials

**All stored EnvVault references are discovered by default, with injection
authorized by saved destination rules.** The sandbox receives public references,
never their resolved values in its environment, files, or native Microsandbox
secret configuration. The default host settings are:

```json
"envvault": true,
"envvault_scope": "profiles"
```

The proxy discovers credentials from EnvVault's normal host configuration and
resolves the selected value through EnvVault's OS keyring provider for each
request. There is no per-sandbox credential registration or helper binary.
Saved proxy profiles provide the destination rules, including workspace
bindings. Network rules also apply: a credential can be sent only to an allowed
public HTTPS host on port 443. A reference without a saved destination rule is
discoverable but cannot be injected by default.

Store or rotate a credential **on your Mac** using the normal EnvVault prompt:

```sh
envvault credential set github/agent
```

Save its destination rule once in EnvVault on the Mac:

```sh
envvault proxy add github-agent --credential github/agent \
  --provider generic --target https://api.github.com \
  --allow-method GET --allow-path /user
```

Existing proxy profiles are imported automatically; do not duplicate them in
the sandbox policy. Allow `api.github.com` in the host policy's `https_hosts`.
In the sandbox:

```sh
curl -fsS -H 'Authorization: Bearer envvault://github/agent' https://api.github.com/user
```

For an SDK that loads `.env`, use its usual variable name with a public handle:

```dotenv
GITHUB_TOKEN=envvault://github/agent
```

The default profile mode supports `Authorization: Bearer envvault://…` and
GitHub CLI's `Authorization: token envvault://…`. It
substitutes only the selected authentication header; query strings, request
bodies, arbitrary headers, shell output, and non-HTTP protocols are not
credential resolvers.
Unknown references, proxy output references such as `/token`, ambiguous
credential headers, and malformed paths are denied before keyring access.

The guest's public catalog is `/etc/envvault/credentials.json`, also identified
by `ENVVAULT_CREDENTIALS_FILE`. It lists references and saved routing metadata,
contains no values, and is readable but not writable by the agent. The host
updates it atomically on the 250 ms polling cycle. It does not mount the host's
EnvVault configuration or OS credential store.

Adding, rotating, or deleting a credential applies without restarting. Deletion
also revokes existing tunnels within the polling cycle. Invalid host metadata
blocks requests and clears the guest catalog until the host fixes it.
`"envvault": false` disables automatic credential access live.

The default `profiles` scope automatically imports all saved provider-proxy
profiles allowed for the workspace and checks their host, method, exact path,
base path, and project binding. A reference with no matching profile remains
discoverable but cannot be injected in this mode.

Profile edits and removal apply live, including revocation of existing streams.
This mode supports public DNS HTTPS:443 Bearer profiles. Private destinations
and unsupported protocols are not enabled by importing a profile.

For an explicit broader setting, `"envvault_scope": "network"` allows any
stored credential on any network-allowed host, without saved profile destination
or workspace restrictions. This mode also supports bare references in
`X-API-Key`, `Api-Key`, and `X-Goog-Api-Key`. This is not the default.

The optional sandbox `credentials` array remains available for explicit scopes
and variable initialization. An explicit entry overrides automatic access for
its hostname in either mode:

```json
"credentials": [
  {
    "env": "GITHUB_TOKEN",
    "ref": "envvault://github/agent",
    "host": "api.github.com",
    "methods": ["GET"],
    "paths": ["/user"]
  }
]
```

On launch, the guest receives `GITHUB_TOKEN=envvault://github/agent`. Inside the
VM, a normal request uses that reference:

```sh
curl -fsS -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user
```

Explicit bindings use Bearer authentication (`Authorization` by default;
`header` can select another permitted header name), exact methods and paths,
and one entry per hostname. A hostname must also be in `https_hosts`.
Environment variables from this array are initialized at launch. New references
are available live through the catalog and requests, but the host cannot rewrite
an existing process environment. With no explicit entry, automatic EnvVault
access remains available; removing an explicit binding restores that default.

Codex's native ChatGPT login remains in its dedicated guest home; it is not
converted to an EnvVault-held credential by this integration.

## GitHub CLI in the sandbox

`gh` is installed in the prepared image. Allow `api.github.com` in the active
host network policy and save a matching EnvVault destination rule, as in the
GitHub `/user` example above. In the sandbox, run:

```sh
GH_TOKEN=envvault://github/agent gh api user --jq .login
```

[`GH_TOKEN`](https://cli.github.com/manual/gh_help_environment) holds only the
public reference. No `gh auth login` or copy of the Mac's GitHub configuration
is needed. The proxy accepts GitHub CLI's `token` header format, verifies the
same destination/method/path/reference rules, and sends the upstream credential
using Bearer authentication. The image already trusts the session's public CA
and uses the host HTTPS proxy.

The `/user` example authorizes only that endpoint. Other commands need their
actual endpoints authorized: for example, many issue and pull-request commands
use `POST /graphql`, and some also use repository REST endpoints. These rules
remain exact; allowing `github.com` alone does not authorize `api.github.com`.
Git operations such as clone/push, which use Git HTTPS Basic authentication or
SSH, are not covered by the reference substitution bridge. Native HTTPS login
can instead use the persistent guest home, as described below.

`./agent agent-check` runs the real Linux `gh` binary against a local HTTPS
fixture standing in for `api.github.com`. It verifies host-side substitution,
rotation, and denial of an unlisted API path without using your GitHub account
or token. This checks the client/proxy integration rather than account access.

## Host-managed GitHub authentication

The launcher supports EnvVault's encrypted JSON/YAML authentication profiles.
Sign in once on the host with the updated CLI, then use a reference in every VM:

```sh
env -u GOROOT go build -o /tmp/envvault-dev ../../cmd/envvault
/tmp/envvault-dev auth login github --name github/work
/tmp/envvault-dev proxy add github-api --credential github/work \
  --target https://api.github.com --allow-method GET --allow-path /user
/tmp/envvault-dev proxy add github-git --credential github/work \
  --git-repository trknhr/envvault
./agent shell
```

Allow `api.github.com` and `github.com` in the host policy. Inside the guest:

```sh
GH_TOKEN=envvault://github/work gh api user --jq .login
git clone https://github.com/trknhr/envvault.git /tmp/envvault-copy
```

Git's installed credential helper selects a unique reference from the public
route catalog. The host proxy inserts the real HTTPS credential. Repository
rules are read-only unless created with `--git-write`; host rule edits apply
live. The helper does not read or store a real token. See
[Host authentication profiles](../../docs/auth-profiles.md) for import, supported
refresh, profile attachment, config version 2 compatibility, and migration.

## Persistent native GitHub login

To use GitHub's own login once and reuse it across VM launches, allow
`github.com` and `api.github.com` in `https_hosts`, and explicitly add this to
the active host policy:

```json
"native_auth_hosts": ["github.com", "api.github.com"]
```

Inside `./agent shell`, run:

```sh
unset GH_TOKEN GITHUB_TOKEN
gh auth login --hostname github.com --git-protocol https --web
gh auth setup-git --hostname github.com
gh api user --jq .login
```

Complete device approval in your Mac browser. GitHub login and Git's credential
helper are saved under the project's persistent `/home/agent`; new VMs using
that project reuse the login without another approval. The Mac's normal GitHub
configuration is not mounted. Native logins are not copied between projects.

For `native_auth_hosts`, requests without an EnvVault reference can use the
guest's own credential. GitHub token permissions and the sandbox network
allowlist govern those native requests; EnvVault profile path/method rules do
not restrict them. Reference-bearing requests still require their saved
EnvVault destination rules. Native access is an explicit host permission, with
an empty default. Removing it revokes existing connections on the live polling
cycle. Other hosts keep their existing credential rules.

Native login exposes a real token to sandbox applications. On the local Linux
VM, `gh` reported saving it in a plain text file in the persistent guest home.
For host-only keys, use the reference/proxy workflow instead.

On 2026-11-06, native device login succeeded, a fresh VM reused the login for
`gh api user`, and `git ls-remote` reached this repository over HTTPS. This was
a read-only Git check; write permissions and pushing were not tested.

## Compatibility smoke test

This is a custom Go compatibility test for EnvVault, using Microsandbox SDK and
runtime **0.7.13**. Its policy is defined by `main.go`; it is not Microsandbox's
default policy or an implemented `envvault sandbox` runtime adapter.

The example is a separate Go module. EnvVault's root `go.mod` and normal build
do not depend on Microsandbox or its CGO/native libraries.

## Run on the Mac

Requires Apple Silicon, Go 1.25 or newer, CGO enabled, and a C compiler (Xcode
Command Line Tools). Go 1.27.3 was used for the local check.

```sh
cd examples/microsandbox

# Installs/checks the version-matched runtime in the trial's own directory.
env -u GOROOT GOPROXY=https://proxy.golang.org,direct GOSUMDB=sum.golang.org \
  go run . -setup

# Runs the checks and removes the VM afterwards.
env -u GOROOT GOPROXY=https://proxy.golang.org,direct GOSUMDB=sum.golang.org \
  go run .
```

The commands explicitly select the public Go module proxy. The first run
downloads the native runtime and guest image. Runtime files, image caches, and
metadata are isolated under `~/.envvault-msb-trial/`, unless you explicitly set
`MSB_HOME`. The short path avoids macOS's Unix socket path limit. Choose a fresh
short directory rather than moving an existing runtime home: cached image
metadata contains absolute paths.

The test creates a uniquely named Alpine 3.23 VM with 512 MiB memory and one
CPU. It mounts no project directory or host home. Outbound traffic is denied
except DNS and TCP to the temporary loopback receiver on the Mac. Image pulling
uses anonymous registry access, independently of the guest network policy.

## Verified locally

On 2026-11-02, the Go example passed these checks on this Apple Silicon Mac:

- Boot a Linux microVM using the Go SDK.
- Deliver a placeholder to the guest and substitute a fake credential on the host.
- Rotate an existing secret from a host environment source with
  `ModificationPolicyNoRestart`.
- Remove and restore that secret's permitted destination without restarting.
- Block direct traffic to an unlisted internet destination.
- Keep the same Linux boot ID throughout the changes.

The example generates fake credentials in memory and never reads the EnvVault
credential store. Its local receiver never logs or echoes authorization headers.
For this canary check only, the receiver uses plain HTTP and the secret has
`RequireTLSIdentity=false`. Real provider integrations must use verified TLS.
Only the `authorization` header is selected for substitution.

This default smoke test checks the VM and native secret APIs. The `./agent`
commands above provide the separate interactive Codex launcher. On 2026-11-06,
`./agent agent-check` (run from the EnvVault repository root through the wrapper's
full path) also passed real-VM checks for live host rules, blocked
direct egress, default enforcement of saved destination rules, a read-only
reference catalog, live credential addition, rotation and revocation, explicit
network mode with Bearer and API-key headers, and kernel process-limit
exhaustion and recovery with the same boot ID. It uses disposable credentials in
an encrypted host authentication document with an in-memory wrapping-key store;
it does not access your OS credential store or sign in to Codex. On 2026-11-09,
the check additionally passed managed-auth rotation/revocation, `gh api` through
a placeholder, and actual Git clone/push against a disposable local HTTPS Git
server with live repository read/write permissions. No GitHub writes occurred.
The installed launcher also passed these VM checks from a separate temporary
project with spaces in its path, confirming that its workspace follows the
invocation directory rather than the EnvVault source checkout.

The race-enabled proxy tests cover live stream and upgrade revocation, hostname
binding, private-address rejection, scoped credential acquisition, rotation,
revocation, and redacted provider failures:

```sh
env -u GOROOT GOPROXY=https://proxy.golang.org,direct GOSUMDB=sum.golang.org \
  go test -race .
```

## Fit with EnvVault

The existing boundaries provide useful integration points:

- `internal/sandbox.Runtime`: lifecycle for an EnvVault-owned VM.
- `internal/sandbox.EgressAttacher`: deliver a broker endpoint and public CA.
- `internal/connection.CredentialProvider`: keep credential acquisition on the host.
- `internal/providerproxy.OutboundBroker`: preserve provider URLs while checking
  requests and substituting credential references.

The agent launcher reuses `CredentialProvider`, the OS store, configuration
metadata, and the provider-profile translator directly, with live policy and
credential checks in its own Go proxy. It does not yet implement a Microsandbox
adapter for `envvault sandbox run` or report a core `brokered-enforced` session
capability. The native SDK stays in this separate example module.

**Live host rule updates are required.** In 0.7.13, `ModifyOptions` supports
secrets and other configuration changes but has no general network-policy
replacement field. The agent launcher's host proxy implements live destination
updates independently of that API. EnvVault's current production outbound
broker captures its routes at startup and retrieves current credentials per
approved request; carrying live host,
method, and path policy updates into that broker remains separate integration
work.

The SDK's raw `Value` secret input is persisted in durable sandbox configuration;
`SecretModifySpec.Store` is currently unsupported. The agent integration avoids
that API: it passes only references to the VM and acquires values in the host
proxy. The separate default smoke test still uses disposable native-secret
canaries only.

Upstream references: [Go SDK](https://github.com/superradcompany/microsandbox/tree/sdk/go/v0.7.13/sdk/go),
[modification API](https://docs.microsandbox.dev/sdk/go/sandbox#sbmodify),
[networking](https://docs.microsandbox.dev/sdk/go/networking).
Microsandbox describes itself as beta software.
