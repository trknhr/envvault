import { spawn } from 'node:child_process';

export const PROTOCOL = 'envvault.sandbox-plugin/v1';
const MAX_LINE_BYTES = 256 * 1024;

// The plugin's stdout contains capabilities. Never forward its output or put
// an untrusted response/child-process error into a diagnostic.
export class PluginClient {
  constructor(command, args, { timeoutMs = 30_000, spawnImpl = spawn } = {}) {
    this.timeoutMs = timeoutMs;
    this.pending = new Map();
    this.sequence = 0;
    this.buffer = Buffer.alloc(0);
    this.child = spawnImpl(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    this.closed = new Promise((resolve) => { this.resolveClosed = resolve; });
    this.child.stderr.resume();
    this.child.stdin.on('error', () => this.fail());
    this.child.stdout.on('data', (chunk) => this.receive(chunk));
    this.child.on('error', () => this.fail());
    this.child.on('close', () => this.fail());
  }

  fail() {
    if (this.failed) return;
    this.failed = true;
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error('EnvVault plugin connection closed or returned an invalid response'));
    }
    this.pending.clear();
    this.buffer = Buffer.alloc(0);
    this.resolveClosed();
  }

  receive(chunk) {
    if (this.failed) return;
    this.buffer = Buffer.concat([this.buffer, chunk]);
    let newline;
    while ((newline = this.buffer.indexOf(10)) !== -1) {
      if (newline > MAX_LINE_BYTES) return this.fail();
      let response;
      try { response = JSON.parse(this.buffer.subarray(0, newline).toString('utf8')); }
      catch { return this.fail(); }
      this.buffer = this.buffer.subarray(newline + 1);
      const pending = this.pending.get(response?.id);
      if (!pending || response.protocol !== PROTOCOL || typeof response.ok !== 'boolean') return this.fail();
      this.pending.delete(response.id);
      clearTimeout(pending.timer);
      if (response.ok) pending.resolve(response);
      else {
        const code = response.error?.code;
        pending.reject(new Error(/^ENVVAULT_[A-Z_]+$/.test(code ?? '')
          ? `EnvVault plugin rejected the request (${code})`
          : 'EnvVault plugin rejected the request'));
      }
    }
    if (this.buffer.length > MAX_LINE_BYTES) this.fail();
  }

  request(method, payload, timeoutMs = this.timeoutMs) {
    if (this.failed) return Promise.reject(new Error('EnvVault plugin is unavailable'));
    const id = `bridge-${++this.sequence}`;
    const message = { protocol: PROTOCOL, id, method };
    if (payload !== undefined) message[method] = payload;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error('EnvVault plugin request timed out'));
        this.fail();
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin.write(`${JSON.stringify(message)}\n`);
    });
  }

  async dispose(leaseID) {
    if (leaseID && !this.failed) {
      try { await this.request('close', { lease_id: leaseID }, 1_000); }
      catch { /* EOF/process termination also revokes all leases. */ }
    }
    this.child.stdin.end();
    const terminate = setTimeout(() => this.child.kill('SIGTERM'), 1_000);
    const kill = setTimeout(() => this.child.kill('SIGKILL'), 2_000);
    try {
      // `closed` can also mean a malformed response, so wait for process exit.
      if (this.child.exitCode === null && this.child.signalCode === null) {
        await new Promise((resolve) => this.child.once('close', resolve));
      }
    } finally {
      clearTimeout(terminate);
      clearTimeout(kill);
      this.fail();
    }
  }
}
