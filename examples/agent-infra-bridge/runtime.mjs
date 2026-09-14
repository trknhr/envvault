import { accessSync, constants as fsConstants, readFileSync, realpathSync } from 'node:fs';
import { delimiter, dirname, isAbsolute, resolve } from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const AGENT_INFRA_VERSION = '0.9.13';

export function resolveExecutable(name, path = process.env.PATH ?? '') {
  const candidates = isAbsolute(name) || name.includes('/')
    ? [resolve(name)] : path.split(delimiter).filter(Boolean).map((dir) => resolve(dir, name));
  for (const candidate of candidates) {
    try {
      accessSync(candidate, fsConstants.X_OK);
      return realpathSync(candidate);
    } catch { /* Try the next PATH entry. */ }
  }
  throw new Error('Executable not found; check --agent-infra and PATH');
}

export function buildExecArgs(id, environment, command, interactive) {
  // Values stay in the Docker CLIENT environment, never in argv or a file.
  return ['exec', '-i', ...(interactive ? ['-t'] : []), '--workdir', '/workspace',
    ...Object.keys(environment).sort().flatMap((name) => ['--env', name]), id, ...command];
}

// node-pty reports signal: 0 for a normal exit. agent-infra 0.9.13 treats
// any numeric signal as 128 + signal, so normalize only the no-signal case.
export function normalizePtyExit(child) {
  return {
    onData: (callback) => child.onData(callback),
    onExit: (callback) => child.onExit((event) => callback({
      ...event, signal: event.signal === 0 ? undefined : event.signal,
    })),
    write: (data) => child.write(data),
    resize: (cols, rows) => child.resize(cols, rows),
    kill: (signal) => child.kill(signal),
  };
}

function stopOnAbort(signal, child, onClose) {
  let killTimer;
  const stop = () => {
    try { child.kill('SIGTERM'); } catch { /* Already exited. */ }
    killTimer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch { /* Already exited. */ }
    }, 1_000);
    killTimer.unref();
  };
  signal.addEventListener('abort', stop, { once: true });
  if (signal.aborted) stop();
  onClose(() => {
    clearTimeout(killTimer);
    signal.removeEventListener('abort', stop);
  });
}

export function runCommand(command, args, { environment, signal, spawnImpl = spawn }) {
  signal.throwIfAborted();
  return new Promise((resolveCode, reject) => {
    const child = spawnImpl(command, args, { stdio: 'inherit', env: environment });
    stopOnAbort(signal, child, (callback) => child.once('close', callback));
    child.once('error', () => reject(new Error('Could not start Docker sandbox command')));
    child.once('close', (code) => resolveCode(code ?? 1));
  });
}

export async function loadAgentInfra(binary) {
  if (process.platform !== 'darwin') throw new Error('This first adapter supports macOS with Docker Desktop only');
  const cli = resolveExecutable(binary);
  const root = resolve(dirname(cli), '../..');
  let pkg;
  try { pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8')); }
  catch { throw new Error('Cannot locate the agent-infra npm package from its executable'); }
  if (pkg.name !== '@fitlab-ai/agent-infra' || pkg.version !== AGENT_INFRA_VERSION) {
    throw new Error(`This experimental adapter requires agent-infra ${AGENT_INFRA_VERSION}`);
  }
  // agent-infra has no public environment-injection + clipboard entry point.
  // Keep all version-specific imports here and reject unknown versions above.
  const names = ['config', 'constants', 'engine', 'shell', 'recovery', 'agent-client-reconciler',
    'workspace-identity', 'commands/list-running', 'commands/enter', 'clipboard/bridge', 'clipboard/node-pty'];
  let modules;
  try { modules = await Promise.all(names.map((name) => import(pathToFileURL(resolve(root, `dist/lib/sandbox/${name}.js`)).href))); }
  catch { throw new Error('Cannot load the supported agent-infra sandbox modules'); }
  const [configModule, paths, engines, shell, recovery, hooks, identities, listing, enter, clipboard, pty] = modules;
  return {
    async prepare(branch, interactive) {
      if (interactive && (!process.stdin.isTTY || !process.stdout.isTTY)) throw new Error('Image paste requires a terminal; use --non-interactive for scripted commands');
      if (interactive && !await pty.loadNodePty()) throw new Error('agent-infra clipboard dependency is missing; reinstall it with --include=optional');
      try {
        const config = configModule.loadConfig();
        const engine = engines.detectEngine(config);
        if (engine !== 'docker-desktop') throw new Error('unsupported engine');
        const endpoint = JSON.parse(shell.runEngine(engine, 'docker', [
          'context', 'inspect', 'desktop-linux', '--format', '{{json .Endpoints.docker.Host}}',
        ]));
        if (typeof endpoint !== 'string' || !endpoint.startsWith('unix://')) throw new Error('Remote Docker contexts are unsupported');
        paths.assertValidBranchName(branch);
        const target = identities.resolveSandboxTarget(branch, config.repoRoot);
        if (target.workspace.mode !== 'branch-only' || target.branch !== branch) throw new Error('Only branch-only sandboxes are supported');
        const rows = listing.fetchSandboxRows(engine, paths.sandboxLabel(config), paths.sandboxBranchLabel(config), {
          mode: paths.sandboxWorkspaceModeLabel(config), taskId: paths.sandboxTaskIdLabel(config),
        });
        const row = listing.selectSandboxContainer(rows.running, paths.containerNameCandidates(config, branch));
        if (!row || row.workspaceMode !== 'branch-only' || row.branch !== branch) throw new Error('No matching running branch-only sandbox');
        const ready = await recovery.ensureSandboxReady({ config, engine, branch, workspace: target.workspace, row, allowRecreate: false });
        const plan = hooks.createSandboxCapabilityPlan(config);
        const results = await hooks.runSandboxHooks({
          hooks: plan.hooksByPhase['before-enter'], phase: 'before-enter',
          context: { config, plan, enter: { hostHome: config.home, hostEnv: { ...process.env } } },
          runCommand: hooks.runBoundedSandboxHookCommand,
        });
        if (results.some((result) => result.status === 'fatal')) throw new Error('agent-infra entry hook failed');
        // Resolve a full ID and pin the exec to it: a replacement container
        // with the same name must not inherit this sandbox's lease.
        const inspection = JSON.parse(shell.runEngine(engine, 'docker', ['inspect', '--format',
          '{"id":{{json .Id}},"running":{{json .State.Running}},"labels":{{json .Config.Labels}}}', ready.container]));
        if (!/^[a-f0-9]{64}$/.test(inspection.id) || !inspection.running
            || inspection.labels?.[paths.sandboxBranchLabel(config)] !== branch
            || inspection.labels?.[paths.sandboxWorkspaceModeLabel(config)] !== 'branch-only'
            || !Object.hasOwn(inspection.labels, paths.sandboxLabel(config))) throw new Error('Sandbox identity changed');
        let remote = '';
        try { remote = execFileSync('git', ['config', '--get', 'remote.origin.url'], { cwd: config.repoRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); }
        catch { /* Local repositories need not have a remote. */ }
        return { id: inspection.id, engine, home: config.home,
          project: { root: realpathSync(config.repoRoot), ...(remote ? { git_remote: remote } : {}) } };
      } catch {
        throw new Error('Sandbox preparation failed. Use a running branch-only Docker Desktop sandbox and verify agent-infra sandbox exec works first.');
      }
    },
    async run(sandbox, environment, command, { interactive, signal }) {
      signal.throwIfAborted();
      const dockerArgs = buildExecArgs(sandbox.id, environment, command, interactive);
      const clientEnvironment = { ...process.env, ...environment };
      try {
        if (!interactive) {
          const invocation = shell.commandForEngine(sandbox.engine, 'docker', dockerArgs);
          return await runCommand(invocation.cmd, invocation.args, { environment: clientEnvironment, signal });
        }
        // Unlike agent-infra's custom-command CLI path, this explicitly uses
        // its image-paste PTY for any command, including bash and codex.
        dockerArgs.splice(3, 0, ...enter.terminalEnvFlags(), ...enter.hostTimezoneEnvFlags());
        return await clipboard.runInteractiveWithClipboardBridge({
          engine: sandbox.engine, container: sandbox.id, home: sandbox.home,
          dockerArgs, env: clientEnvironment,
          runInteractive: () => { throw new Error('Clipboard bridge unavailable'); },
          loadPty: async () => {
            const implementation = await pty.loadNodePty();
            if (!implementation) return null;
            return { spawn: (...args) => {
              signal.throwIfAborted();
              const child = normalizePtyExit(implementation.spawn(...args));
              stopOnAbort(signal, child, (callback) => child.onExit(callback));
              return child;
            } };
          },
        });
      } catch {
        throw new Error('Sandbox command or clipboard bridge failed; the EnvVault lease will be revoked');
      }
    },
  };
}
