#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { PluginClient } from './plugin-client.mjs';

export const USAGE = `Usage: node bridge.mjs <branch> --env NAME=envvault://profile/base-url
  --env NAME=envvault://profile/token [options] [-- command [args...]]

Options:
  --env ASSIGNMENT          Provider-proxy output only; repeatable
  --envvault PATH           EnvVault executable (default: envvault)
  --agent-infra PATH        agent-infra 0.9.13 executable (default: agent-infra)
  --non-interactive        Run an explicit command without a TTY or clipboard
  --help                   Show this help

Run on macOS, in the agent-infra project, with its Docker Desktop sandbox
already running. The default command is a fresh bash shell with image paste.
No raw credentials, MCP OAuth, tmux reattachment, or egress enforcement.
`;

// These names would alter the HOST Docker client's execution or connection.
// Only application variables may be passed using Docker's name-only -e form.
const RESERVED = /^(?:PATH|HOME|USER|LOGNAME|SHELL|ENV|BASH_ENV|BASHOPTS|SHELLOPTS|IFS|CDPATH|TMPDIR|TMP|TEMP|TERM|TERMINFO|TERMINFO_DIRS|COLORTERM|LANG|LANGUAGE|CODEX_HOME|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|SSL_CERT_FILE|SSL_CERT_DIR|NODE_EXTRA_CA_CERTS|NODE_OPTIONS|NODE_PATH|DOCKER.*|BUILDKIT.*|BUILDX.*|LD_.*|DYLD_.*|LC_.*|GIT_.*|SSH_.*|NPM_.*|PYTHON.*)$/;

export function parseArgs(args) {
  const options = { envvault: 'envvault', agentInfra: 'agent-infra', assignments: [], command: [], interactive: true };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help') return { help: true };
    if (arg === '--') {
      options.command = args.slice(i + 1);
      if (!options.command.length) throw new Error('Expected a command after --');
      break;
    }
    if (arg === '--non-interactive') { options.interactive = false; continue; }
    if (['--env', '--envvault', '--agent-infra'].includes(arg)) {
      const value = args[++i];
      if (!value || value.startsWith('--') || value.includes('\0')) throw new Error(`Missing value for ${arg}`);
      if (arg === '--env') options.assignments.push(value);
      else options[arg === '--envvault' ? 'envvault' : 'agentInfra'] = value;
      continue;
    }
    if (arg.startsWith('-') || options.branch) throw new Error('Unexpected bridge argument; see --help');
    options.branch = arg;
  }
  if (!options.branch) throw new Error('An agent-infra branch is required');
  if (!options.interactive && !options.command.length) throw new Error('--non-interactive requires -- command');
  if (!options.command.length) options.command = ['bash', '-i'];
  options.bindings = parseBindings(options.assignments);
  return options;
}

export function parseBindings(assignments) {
  const profiles = new Map();
  const names = new Set();
  for (const assignment of assignments) {
    const match = /^([A-Z][A-Z0-9_]*)=envvault:\/\/([A-Za-z0-9][A-Za-z0-9._/-]*)\/(base-url|token)$/.exec(assignment);
    if (!match) throw new Error('--env must map an uppercase variable to an EnvVault base-url or token reference');
    const [, environment, profile, part] = match;
    if (RESERVED.test(environment)) throw new Error('Host runtime/control environment variables cannot be used as outputs');
    if (names.has(environment)) throw new Error('Duplicate output environment variable');
    if (profile.split('/').some((segment) => !segment || segment === '.' || segment === '..')) throw new Error('Invalid provider-proxy profile name');
    names.add(environment);
    if (!profiles.has(profile)) profiles.set(profile, { profile, outputs: [] });
    profiles.get(profile).outputs.push({ environment, part });
  }
  if (!profiles.size || profiles.size > 32 || names.size > 64) throw new Error('Provide outputs for 1–32 provider-proxy profiles (at most 64 variables)');
  for (const binding of profiles.values()) {
    if (binding.outputs.length > 32 || !binding.outputs.some((output) => output.part === 'base-url')
        || !binding.outputs.some((output) => output.part === 'token')) {
      throw new Error('Each profile needs both base-url and token outputs (at most 32 aliases)');
    }
  }
  return [...profiles.values()];
}

export function validateLease(lease, sandboxID, bindings, now = Date.now()) {
  const expected = bindings.flatMap((binding) => binding.outputs.map((output) => output.environment)).sort();
  const environment = lease?.environment;
  const expires = Date.parse(lease?.expires_at);
  if (!lease || lease.sandbox_id !== sandboxID || lease.security_level !== 'brokered'
      || typeof lease.lease_id !== 'string' || !/^plugin_[A-Za-z0-9]+$/.test(lease.lease_id)
      || !environment || Array.isArray(environment) || typeof environment !== 'object'
      || JSON.stringify(Object.keys(environment).sort()) !== JSON.stringify(expected)
      || Object.values(environment).some((value) => typeof value !== 'string' || !value || /[\0\r\n]/.test(value))
      || !Number.isFinite(expires) || expires <= now) {
    throw new Error('EnvVault returned an invalid or expired lease');
  }
  return expires;
}

// runtime.prepare performs identity/readiness checks BEFORE credentials open.
export async function runBridge(options, {
  runtime,
  createClient = () => new PluginClient(options.envvault, [
    'sandbox', 'plugin', 'serve', '--gateway-listen', '0.0.0.0:0', '--gateway-host', 'host.docker.internal'
  ]),
  signal = new AbortController().signal,
  status = (message) => process.stderr.write(`${message}\n`),
} = {}) {
  signal.throwIfAborted();
  const sandbox = await runtime.prepare(options.branch, options.interactive);
  signal.throwIfAborted();
  const client = createClient();
  const session = new AbortController();
  const abort = () => session.abort(new Error('Bridge interrupted'));
  signal.addEventListener('abort', abort, { once: true });
  if (signal.aborted) abort();
  let lease;
  let expiryTimer;
  let completed = false;
  client.closed.then(() => {
    if (!completed) session.abort(new Error('EnvVault plugin disconnected; access revoked'));
  });
  const stopped = new Promise((_, reject) => {
    if (session.signal.aborted) reject(session.signal.reason);
    else session.signal.addEventListener('abort', () => reject(session.signal.reason), { once: true });
  });
  // Avoid an unhandled rejection if a signal arrives between protocol awaits.
  stopped.catch(() => {});
  try {
    await Promise.race([client.request('ping'), stopped]);
    const response = await Promise.race([client.request('open', {
      sandbox_id: sandbox.id,
      project: sandbox.project,
      bindings: options.bindings,
    }), stopped]);
    lease = response.lease;
    const expires = validateLease(lease, sandbox.id, options.bindings);
    const checkExpiry = () => {
      const remaining = expires - Date.now();
      if (remaining <= 0) session.abort(new Error('EnvVault lease expired; start a new bridge session'));
      else expiryTimer = setTimeout(checkExpiry, Math.min(remaining, 2_147_483_647));
    };
    checkExpiry();
    session.signal.throwIfAborted();
    status(`EnvVault bridge: brokered API access until ${new Date(expires).toISOString()}; direct egress is not blocked.`);
    const code = await Promise.race([
      runtime.run(sandbox, lease.environment, options.command, { interactive: options.interactive, signal: session.signal }),
      stopped,
    ]);
    return code;
  } finally {
    completed = true;
    clearTimeout(expiryTimer);
    session.abort(new Error('Bridge session closed'));
    signal.removeEventListener('abort', abort);
    await client.dispose(lease?.lease_id);
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) { process.stdout.write(USAGE); return 0; }
  const { loadAgentInfra } = await import('./runtime.mjs');
  const runtime = await loadAgentInfra(options.agentInfra);
  const controller = new AbortController();
  const interrupt = () => controller.abort();
  for (const name of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(name, interrupt);
  try { return await runBridge(options, { runtime, signal: controller.signal }); }
  finally { for (const name of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.off(name, interrupt); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  main().then((code) => { process.exitCode = code; }).catch((error) => {
    // Our protocol/runtime boundaries deliberately do not retain raw child errors.
    process.stderr.write(`envvault-agent-infra: ${error.message}\n`);
    process.exitCode = 1;
  });
}
