import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseArgs, parseBindings, runBridge, validateLease } from '../bridge.mjs';
import { PluginClient } from '../plugin-client.mjs';
import { buildExecArgs, normalizePtyExit, runCommand } from '../runtime.mjs';

const assignments = ['SERVICE_URL=envvault://service/dev/base-url', 'SERVICE_TOKEN=envvault://service/dev/token'];
const options = () => parseArgs(['clipboard-test', ...assignments.flatMap((a) => ['--env', a])]);
const environment = { SERVICE_URL: 'http://127.0.0.1:12345/service/dev', SERVICE_TOKEN: 'CAPABILITY_CANARY' };
const lease = () => ({
  lease_id: 'plugin_test', sandbox_id: 'sandbox-test', security_level: 'brokered',
  expires_at: new Date(Date.now() + 60_000).toISOString(), environment: { ...environment },
});

test('parses repeated profiles/aliases and passes the child argv unchanged', () => {
  const parsed = parseArgs(['branch', '--env', assignments[0], '--env', assignments[1],
    '--env', 'OTHER_TOKEN=envvault://service/dev/token', '--', 'node', '-e', 'console.log("test")']);
  assert.equal(parsed.bindings.length, 1);
  assert.equal(parsed.bindings[0].outputs.length, 3);
  assert.deepEqual(parsed.command, ['node', '-e', 'console.log("test")']);
  assert.deepEqual(options().command, ['bash', '-i']);
});

test('rejects raw secrets, direct refs, host controls, duplicates, and incomplete bindings', () => {
  for (const bad of ['API_KEY=raw-secret', 'API_KEY=envvault://direct-key', 'lower=envvault://p/token',
    'PATH=envvault://p/token', 'NODE_OPTIONS=envvault://p/token', 'DOCKER_HOST=envvault://p/token',
    'HOME=envvault://p/token', 'API_KEY=envvault://p/../token', 'API_KEY=envvault://p//token']) {
    assert.throws(() => parseBindings([bad]));
  }
  assert.throws(() => parseBindings([assignments[0]]));
  assert.throws(() => parseBindings([...assignments, assignments[1]]));
  assert.throws(() => parseArgs(['branch', '--non-interactive', '--env', assignments[0], '--env', assignments[1]]));
});

test('validates exact lease identity, outputs, values, security level and expiry', () => {
  const bindings = options().bindings;
  assert.ok(validateLease(lease(), 'sandbox-test', bindings));
  for (const mutate of [
    (l) => { l.sandbox_id = 'other'; },
    (l) => { l.expires_at = '2000-01-01'; },
    (l) => { l.security_level = 'materialized-static'; },
    (l) => { l.environment.EXTRA = 'x'; },
    (l) => { delete l.environment.SERVICE_TOKEN; },
    (l) => { l.environment.SERVICE_TOKEN = 'bad\nvalue'; },
    (l) => { l.lease_id = ''; },
  ]) {
    const invalid = lease(); mutate(invalid);
    assert.throws(() => validateLease(invalid, 'sandbox-test', bindings));
  }
});

test('Docker argv contains only output names, never capabilities or host env', () => {
  const args = buildExecArgs('container-id', environment, ['bash', '-i'], true);
  assert.deepEqual(args, ['exec', '-i', '-t', '--workdir', '/workspace',
    '--env', 'SERVICE_TOKEN', '--env', 'SERVICE_URL', 'container-id', 'bash', '-i']);
  assert.ok(!JSON.stringify(args).includes('CAPABILITY_CANARY'));
  assert.ok(!JSON.stringify(args).includes(environment.SERVICE_URL));
  assert.ok(!buildExecArgs('container-id', environment, ['true'], false).includes('-t'));
});

test('PTY adapter preserves normal exit codes and real signals', () => {
  for (const [event, expected] of [
    [{ exitCode: 0, signal: 0 }, { exitCode: 0, signal: undefined }],
    [{ exitCode: 17, signal: 0 }, { exitCode: 17, signal: undefined }],
    [{ exitCode: 0, signal: 15 }, { exitCode: 0, signal: 15 }],
  ]) {
    const wrapped = normalizePtyExit({ onExit: (cb) => cb(event) });
    wrapped.onExit((value) => assert.deepEqual(value, expected));
  }
});

function harness({ run = async () => 0, output = lease() } = {}) {
  const events = [];
  let disconnect;
  const client = {
    closed: new Promise((resolve) => { disconnect = resolve; }),
    async request(method, payload) { events.push({ method, payload }); return method === 'open' ? { lease: output } : { ok: true }; },
    async dispose(id) { events.push({ method: 'dispose', id }); disconnect(); },
  };
  const runtime = {
    async prepare() { events.push({ method: 'prepare' }); return { id: 'sandbox-test', project: { root: '/trusted/project' } }; },
    run,
  };
  return { events, client, runtime, disconnect, status: [] };
}

test('checks readiness before opening, preserves child exit code, and closes lease', async () => {
  let captured;
  const h = harness({ run: async (_s, env, command, args) => { captured = { env, command, args }; return 17; } });
  assert.equal(await runBridge(options(), { runtime: h.runtime, createClient: () => h.client, status: (s) => h.status.push(s) }), 17);
  assert.deepEqual(h.events.map((e) => e.method), ['prepare', 'ping', 'open', 'dispose']);
  assert.deepEqual(h.events[2].payload.project, { root: '/trusted/project' });
  assert.deepEqual(captured.env, environment);
  assert.equal(h.events[3].id, 'plugin_test');
  assert.equal(captured.args.signal.aborted, true);
  assert.ok(!h.status.join('').includes('CAPABILITY_CANARY'));
});

test('does not start the broker if sandbox preparation fails', async () => {
  let opened = false;
  await assert.rejects(runBridge(options(), {
    runtime: { prepare: async () => { throw new Error('not ready'); } },
    createClient: () => { opened = true; },
  }), /not ready/);
  assert.equal(opened, false);
});

test('closes leases on workload errors and invalid delivery', async () => {
  for (const invalid of [false, true]) {
    const output = lease();
    if (invalid) output.environment.EXTRA = 'unexpected';
    const h = harness({ output, run: async () => { throw new Error('workload failed'); } });
    await assert.rejects(runBridge(options(), { runtime: h.runtime, createClient: () => h.client, status: () => {} }));
    assert.equal(h.events.at(-1).method, 'dispose');
  }
});

test('interrupt, expiry and broker death abort the workload and revoke the lease', async () => {
  for (const mode of ['interrupt', 'expiry', 'disconnect']) {
    const controller = new AbortController();
    const output = lease();
    if (mode === 'expiry') output.expires_at = new Date(Date.now() + 100).toISOString();
    let sessionSignal;
    const h = harness({ output, run: async (_s, _e, _c, { signal }) => {
      sessionSignal = signal;
      if (mode === 'interrupt') controller.abort();
      if (mode === 'disconnect') h.disconnect();
      return new Promise(() => {});
    } });
    await assert.rejects(runBridge(options(), {
      runtime: h.runtime, createClient: () => h.client, signal: controller.signal, status: () => {},
    }), /interrupted|expired|disconnected/);
    assert.equal(sessionSignal.aborted, true);
    assert.equal(h.events.at(-1).method, 'dispose');
  }
});

const fixture = fileURLToPath(new URL('./protocol-fixture.mjs', import.meta.url));
test('protocol client handles chunked replies and graceful EOF', async () => {
  const client = new PluginClient(process.execPath, [fixture, 'ok']);
  try { assert.equal((await client.request('ping')).status, 'ready'); }
  finally { await client.dispose(); }
});

for (const mode of ['malformed', 'oversized', 'wrong-id', 'reject', 'hang']) {
  test(`protocol client rejects ${mode} without echoing sensitive child output`, async () => {
    const client = new PluginClient(process.execPath, [fixture, mode], { timeoutMs: mode === 'hang' ? 150 : 5_000 });
    try {
      await assert.rejects(client.request('ping'), (error) => !error.message.includes('CAPABILITY_CANARY'));
    } finally { await client.dispose(); }
  });
}

test('missing plugin executable is handled without an uncaught spawn error', async () => {
  const client = new PluginClient('/nonexistent/envvault-bridge-test', []);
  try { await assert.rejects(client.request('ping')); }
  finally { await client.dispose(); }
});

test('noninteractive child launch errors are redacted', async () => {
  await assert.rejects(runCommand('/nonexistent/docker-bridge-test', ['CAPABILITY_CANARY'], {
    environment, signal: new AbortController().signal,
  }), (error) => !error.message.includes('CAPABILITY_CANARY'));
});

test('real EnvVault broker injects upstream credential, enforces paths, and revokes after exit', {
  skip: !process.env.ENVVAULT_BRIDGE_TEST_PLUGIN,
}, async () => {
  let connection;
  const parsed = parseArgs(['test', '--env', 'SERVICE_URL=envvault://bridge-test/base-url', '--env', 'SERVICE_TOKEN=envvault://bridge-test/token']);
  const runtime = {
    prepare: async () => ({ id: 'sandbox-test', project: { root: '/trusted/project' } }),
    async run(_sandbox, env) {
      connection = { ...env };
      assert.notEqual(env.SERVICE_TOKEN, 'ENVVAULT_BRIDGE_UPSTREAM_CANARY_NOT_A_REAL_KEY');
      const headers = { Authorization: `Bearer ${env.SERVICE_TOKEN}` };
      const allowed = await fetch(`${env.SERVICE_URL}/probe`, { headers });
      assert.equal(allowed.status, 200);
      assert.deepEqual(await allowed.json(), { ok: true });
      assert.equal((await fetch(`${env.SERVICE_URL}/blocked`, { headers })).status, 403);
      assert.equal((await fetch(`${env.SERVICE_URL}/probe`)).status, 401);
      assert.equal((await fetch(`${env.SERVICE_URL}/probe`, { headers: { Authorization: 'Bearer invalid' } })).status, 401);
      return 0;
    },
  };
  assert.equal(await runBridge(parsed, {
    runtime, status: () => {},
    createClient: () => new PluginClient(process.env.ENVVAULT_BRIDGE_TEST_PLUGIN, ['sandbox', 'plugin', 'serve']),
  }), 0);
  await assert.rejects(fetch(`${connection.SERVICE_URL}/probe`, { headers: { Authorization: `Bearer ${connection.SERVICE_TOKEN}` } }));
});
