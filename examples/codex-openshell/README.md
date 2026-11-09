# Codex in OpenShell

This local example runs Codex with a separate ChatGPT login inside OpenShell.
It includes Go, Node.js, Git, curl, and ripgrep for developing EnvVault. It
does not import the host Codex home or use the future EnvVault credential
driver. Codex's login state is readable inside this sandbox.

Run these commands on your Mac, from the EnvVault repository root:

```bash
docker build --tag envvault-codex-openshell:local examples/codex-openshell

openshell sandbox create \
  --name envvault-codex \
  --from envvault-codex-openshell:local \
  --policy examples/codex-openshell/policy.yaml \
  --detach \
  --no-auto-providers

openshell sandbox upload envvault-codex . /workspace
openshell sandbox connect envvault-codex
```

Inside the sandbox:

```bash
cd /workspace
codex --version
codex login --device-auth
codex
```

Open the link printed by `codex login --device-auth` in your Mac's browser and
enter the one-time code there. Device code login may need enabling in your
ChatGPT security settings or workspace permissions. See the
[official OpenAI authentication guide](https://learn.chatgpt.com/docs/auth#login-on-headless-devices).

For a first task, ask: `Explain this repository without changing files.`

The project is uploaded as a copy. Edits inside OpenShell are not automatically
written back to the Mac checkout. Use the `openshell sandbox download` command
to retrieve reviewed files before deleting the sandbox.

The network policy permits Codex's ChatGPT authentication and model endpoints,
Go module downloads, and npm's registry. Other destinations remain blocked.
Review additional destinations on the host if your task needs them. Do not
expect the example.com permission from `envvault-trial` to carry over.

The `codex` command links to the native executable at `/opt/codex/bin/codex`
so the policy can match its actual executable path. The host Codex installation and
the existing `envvault-trial` sandbox are independent of this example.
