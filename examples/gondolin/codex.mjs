import assert from "node:assert/strict";
import { mkdir, readFile, access, mkdtemp, writeFile, symlink, rm } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  VM, VmCheckpoint, RealFSProvider, ShadowProvider, createHttpHooks,
} from "@earendil-works/gondolin";

const exampleDir = path.dirname(fileURLToPath(import.meta.url));
const repoDir = path.resolve(exampleDir, "../..");
const policy = JSON.parse(await readFile(path.join(exampleDir, "codex-policy.json"), "utf8"));
const stateDir = path.join(homedir(), ".local/share/envvault-gondolin");
const homeDir = path.join(stateDir, "home");
const snapshotPath = path.join(stateDir, `codex-${policy.codexVersion}.qcow2`);
const mode = process.argv[2] ?? "codex";
if (!["codex", "setup", "login", "shell", "rules", "check"].includes(mode)) {
  throw new Error("Use: node codex.mjs [setup|login|shell|rules|check]");
}

// Keep the rule file honest: unsupported policy changes must fail explicitly.
assert.equal(policy.filesystem.workspaceAccess, "read-write");
assert.equal(policy.network.blockPrivateAddresses, true);
assert.equal(policy.network.dns, "synthetic");
for (const feature of ["ssh", "rawTcp", "ingress"]) assert.equal(policy.network[feature], false);
assert.equal(policy.credentials.hostAgentHomeMounted, false);
assert.equal(policy.credentials.envvaultConnected, false);
assert.equal(policy.credentials.login, "separate-device-auth");
assert.equal(policy.codex.boundary, "gondolin-vm-and-host-hooks");
assert.equal(policy.codex.sandbox, "danger-full-access");
assert.match(policy.codexVersion, /^\d+\.\d+\.\d+$/);

if (mode === "rules") {
  console.log(JSON.stringify({ ...policy, hostPaths: { workspace: repoDir, isolatedHome: homeDir, snapshot: snapshotPath } }, null, 2));
  process.exit(0);
}

await mkdir(stateDir, { recursive: true, mode: 0o700 });
await mkdir(homeDir, { recursive: true, mode: 0o700 });

function network(hosts) {
  return createHttpHooks({
    allowedHosts: hosts,
    blockInternalRanges: policy.network.blockPrivateAddresses,
    isRequestAllowed: (request) => {
      const url = new URL(request.url);
      return url.protocol === "https:" && (url.port === "" || url.port === "443");
    },
  }).httpHooks;
}

const vmDefaults = {
  sandbox: { vmm: policy.vm.backend },
  memory: policy.vm.memory,
  cpus: policy.vm.cpus,
  dns: { mode: policy.network.dns },
  allowWebSockets: policy.network.webSockets,
};

async function checked(vm, command, options = {}) {
  const result = await vm.exec(command, { signal: AbortSignal.timeout(600_000), ...options });
  assert.equal(result.exitCode, 0, "guest command failed");
  return result;
}

async function ensureSnapshot() {
  try {
    await access(snapshotPath);
    return;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  console.log("Preparing Codex and Go tools in a reusable Gondolin snapshot...");
  const vm = await VM.create({
    ...vmDefaults,
    rootfs: { size: policy.vm.rootfsSize },
    httpHooks: network(policy.network.setupHttpsHosts),
    sessionLabel: "envvault-codex-setup",
  });
  try {
    await checked(vm, "apk add --no-cache git ripgrep go build-base", { stdout: "inherit", stderr: "inherit" });
    await checked(vm, `npm install --global --ignore-scripts --no-audit --no-fund @openai/codex@${policy.codexVersion}`, { stdout: "inherit", stderr: "inherit" });
    await checked(vm, "codex --version; go version", { stdout: "inherit", stderr: "inherit" });
    await vm.checkpoint(snapshotPath);
    console.log("Codex snapshot ready.");
  } finally {
    await vm.close();
  }
}

await ensureSnapshot();
if (mode === "setup") process.exit(0);

const fsPolicy = policy.filesystem;
const hidden = new ShadowProvider(new RealFSProvider(repoDir), {
  shouldShadow: ({ path: entry }) => entry.split("/").some((name) =>
    fsPolicy.hiddenNames.includes(name) || fsPolicy.hiddenPrefixes.some((prefix) => name.startsWith(prefix))),
});
const workspace = new ShadowProvider(hidden, {
  shouldShadow: ({ path: entry }) => entry.split("/").some((name) => fsPolicy.ephemeralNames.includes(name)),
  writeMode: "tmpfs",
});
const guestEnv = {
  HOME: fsPolicy.home,
  PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  CODEX_HOME: `${fsPolicy.home}/.codex`,
  GOPATH: `${fsPolicy.home}/go`,
  GOCACHE: `${fsPolicy.home}/.cache/go-build`,
  TERM: process.env.TERM || "xterm-256color",
};
const configArgs = [
  "-c", 'cli_auth_credentials_store="file"',
];
const codexArgs = [
  "--sandbox", policy.codex.sandbox,
  "--ask-for-approval", policy.codex.approval,
  ...configArgs,
];
// SDK argv commands need an absolute executable path; resolve Codex in the guest.
const codexCommand = (...args) => ["/bin/sh", "-c", 'exec codex "$@"', "codex", ...args];
const vm = await VmCheckpoint.load(snapshotPath).resume({
  ...vmDefaults,
  httpHooks: network(policy.network.httpsHosts),
  env: guestEnv,
  vfs: { mounts: { [fsPolicy.workspace]: workspace, [fsPolicy.home]: new RealFSProvider(homeDir) } },
  sessionLabel: "envvault-codex",
});
try {
  await checked(vm, ["/bin/mkdir", "-p", guestEnv.CODEX_HOME]);
  if (mode === "check") {
    await checked(vm, "codex --version; go version; node --version; git --version; rg --version | head -n 1", { stdout: "inherit", stderr: "inherit" });
    await checked(vm, "test -r go.mod && test -w . && test -w \"$HOME\" && test ! -e /Users", { cwd: fsPolicy.workspace });
    console.log("PASS: workspace and dedicated home are accessible; Mac home is not mounted");
    const canaryDir = await mkdtemp(path.join(repoDir, ".gondolin-policy-check-"));
    try {
      await writeFile(path.join(canaryDir, ".env"), "fake-test-marker\n");
      await symlink(".env", path.join(canaryDir, "hidden-alias"));
      await symlink(homedir(), path.join(canaryDir, "outside-alias"));
      const guestCanary = `${fsPolicy.workspace}/${path.basename(canaryDir)}`;
      await checked(vm, ["/bin/sh", "-c", 'test ! -e "$1/.env" && ! cat "$1/hidden-alias" >/dev/null 2>&1 && ! ls "$1/outside-alias" >/dev/null 2>&1 && ! (printf denied > "$1/.env") 2>/dev/null && printf writable > "$1/output"', "check", guestCanary]);
      assert.equal(await readFile(path.join(canaryDir, ".env"), "utf8"), "fake-test-marker\n");
      assert.equal(await readFile(path.join(canaryDir, "output"), "utf8"), "writable");
      console.log("PASS: workspace writes reach the Mac; hidden files and escaping symlinks are blocked");
    } finally {
      await rm(canaryDir, { recursive: true, force: true });
    }
    for (const host of ["auth.openai.com", "chatgpt.com"]) {
      const result = await checked(vm, ["/usr/bin/curl", "--silent", "--show-error", "--max-time", "20", "--output", "/dev/null", "--write-out", "%{http_code}", `https://${host}/`]);
      assert.match(result.stdout, /^[1-5]\d{2}$/);
      assert.notEqual(result.stdout, "502", "allowed host must be reachable");
    }
    console.log("PASS: Codex authentication/model hosts are reachable");
    const denied = await checked(vm, ["/usr/bin/curl", "--silent", "--max-time", "10", "--output", "/dev/null", "--write-out", "%{http_code}", "https://example.com/"]);
    assert.equal(denied.stdout, "403");
    console.log("PASS: unlisted example.com is blocked");
    await checked(vm, "go test ./internal/envref", { cwd: fsPolicy.workspace, stdout: "inherit", stderr: "inherit" });
    console.log("PASS: EnvVault Go package test");
    await checked(vm, codexCommand(...codexArgs, "--help"));
    console.log("PASS: Codex starts with the configured launch arguments");
  } else {
    const command = mode === "login"
      ? codexCommand("-c", 'cli_auth_credentials_store="file"', "login", "--device-auth")
      : mode === "shell" ? ["/bin/bash"] : codexCommand(...codexArgs, ...process.argv.slice(3));
    console.log(`Gondolin: ${fsPolicy.workspace} shares this checkout; ${fsPolicy.home} is the dedicated persistent home.`);
    const result = await vm.shell({ command, cwd: fsPolicy.workspace, env: guestEnv });
    process.exitCode = result.exitCode;
  }
} finally {
  await vm.close();
}
