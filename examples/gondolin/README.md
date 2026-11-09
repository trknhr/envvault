# Gondolin local trial

This example uses Gondolin 0.14.0 with its QEMU backend and default Alpine Linux
image. Node.js 22.19 or newer and QEMU are required on the Mac:

```sh
brew install qemu
npm --prefix examples/gondolin ci
```

Run these commands from the EnvVault repository root.

## Open a shell

```sh
npm --prefix examples/gondolin run shell
```

Inside the VM:

```sh
uname -a
printf 'hello from Gondolin\n' > /tmp/gondolin-test
cat /tmp/gondolin-test
curl -I https://example.com
exit
```

This shell permits HTTP/HTTPS to `example.com`. The first launch downloads the
guest image into `~/.cache/gondolin/images/`. Guest changes are ephemeral when
this shell exits.

To also mount this checkout read-only at `/workspace`:

```sh
npm --prefix examples/gondolin run shell -- \
  --mount-hostfs "$PWD:/workspace:ro" --cwd /workspace
```

Remove `:ro` if you want guest edits to write directly to the Mac checkout.
The default image is a general Linux shell. The Codex commands below prepare a
separate snapshot with the development tools.

## Run Codex

From the EnvVault repository root:

```sh
npm --prefix examples/gondolin run codex:login
```

Open the URL printed in that terminal in your Mac browser and enter its device
code. Device login may need enabling in your ChatGPT security settings or
workspace permissions; see the [official authentication guide](https://learn.chatgpt.com/docs/auth#login-on-headless-devices).
Then start Codex:

```sh
npm --prefix examples/gondolin run codex
```

For a first task, ask: `Explain this repository without changing files.`

The first Codex launch prepares a reusable snapshot with Codex 0.166.0, Go,
Node.js, Git, ripgrep, and C/C++ build tools. The separate login and caches persist
in `~/.local/share/envvault-gondolin/home/` on the Mac. This setup does not import
the host's Codex login or configuration. Login credentials are readable by code
running inside this VM; EnvVault's host-side credential injection is not
connected to this Codex login.

### Codex sandbox rules

The editable host policy is [codex-policy.json](./codex-policy.json). Print it
with resolved host paths:

```sh
npm --prefix examples/gondolin run codex:rules
```

| Area | Rule |
| --- | --- |
| Isolation | QEMU Linux VM, 2 CPUs, 2 GiB memory, 4 GiB root disk |
| Project | This Mac checkout is mounted read/write at `/workspace`; edits affect the Mac immediately |
| Home | Only the dedicated home is mounted at `/home/codex`; the normal Mac home is not mounted |
| Hidden host paths | `.env`, `.env.*`, `.envrc`, `.npmrc`, `.netrc`, and `.envvault-cache`, at any depth; reads are hidden and writes denied |
| Node modules | Host `node_modules` directories are hidden; guest installs there use ephemeral memory |
| Persistence | Project and dedicated home persist; other guest changes are discarded at exit |
| HTTPS | Port 443 to the exact hosts listed below, for every guest program |
| Other networking | Private IP ranges blocked; synthetic DNS; no SSH, raw TCP mapping, or host ingress; WebSockets permitted on allowed HTTPS hosts |
| Codex approvals | `on-request`; Codex can run commands throughout the VM, subject to Gondolin's rules |

Runtime HTTPS destinations:

```text
auth.openai.com
chatgpt.com
api.openai.com
registry.npmjs.org
proxy.golang.org
sum.golang.org
storage.googleapis.com
```

Snapshot preparation separately permits `dl-cdn.alpinelinux.org` and
`registry.npmjs.org`. The preparation VM has no project or persistent home mounted.

Gondolin enforces these filesystem and network boundaries on the host. This
launcher uses Codex's `danger-full-access` mode *inside the VM*: Codex's nested
Linux sandbox currently fails to access Gondolin's FUSE-mounted home
(`bwrap: ... Permission denied`). The mode grants access to the guest VM;
it does not grant access to additional Mac paths or remove Gondolin's network
rules. Codex's `on-request` approval setting remains enabled.

Policy file edits apply on the next launch. The earlier `secretManager` test
demonstrates live secret updates; this launcher does not expose a live policy
control API.

Other useful commands:

```sh
# Shell with the same mounts and network rules as Codex
npm --prefix examples/gondolin run codex:shell

# Verify tools, filesystem rules, network rules, and an EnvVault Go package test
npm --prefix examples/gondolin run codex:check
```

## Check secret injection and live changes

```sh
npm --prefix examples/gondolin run smoke
```

The script creates a temporary loopback HTTP receiver on the Mac, generates fake
credentials in memory, and starts a VM. It checks file I/O, HTTPS to
`example.com`, a guest-visible placeholder, and a header containing the real
fake credential at the receiver. It then rotates the value with
`secretManager.updateSecret()` and removes the receiver from that secret's host
scope. The requests use the same VM throughout; the script also checks that its
Linux boot ID and placeholder did not change after rotation. It closes the VM
and receiver when finished and prints no credential values.

For this local test only, `curl --connect-to` sends the guest connection to
Gondolin's virtual gateway while keeping `127.0.0.1` as the URL hostname. The
HTTP bridge can therefore reach the Mac's loopback receiver. The hook permits
that loopback destination only at the receiver's temporary port and root path.

This proves Gondolin's native secret mechanism. An EnvVault resolver/plugin is
not connected yet; the test does not read or modify stored credentials.

See the upstream [CLI guide](https://earendil-works.github.io/gondolin/cli/)
and [secret handling guide](https://earendil-works.github.io/gondolin/secrets/).
Gondolin describes itself as experimental.
