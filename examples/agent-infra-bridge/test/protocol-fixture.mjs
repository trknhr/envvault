import { createInterface } from 'node:readline';
const mode = process.argv[2];
if (mode === 'hang') {
  process.stdin.resume();
  process.on('SIGTERM', () => {});
  setInterval(() => {}, 1_000);
}
else {
  const input = createInterface({ input: process.stdin });
  input.on('line', (line) => {
    const request = JSON.parse(line);
    if (mode === 'malformed') { process.stdout.write('CAPABILITY_CANARY not JSON\n'); return; }
    if (mode === 'oversized') { process.stdout.write('x'.repeat(256 * 1024 + 1)); return; }
    const response = { protocol: request.protocol, id: request.id, ok: true, status: 'ready' };
    if (mode === 'wrong-id') response.id = 'unexpected';
    if (mode === 'reject') {
      response.ok = false;
      response.error = { code: 'ENVVAULT_PROFILE_NOT_FOUND', message: 'CAPABILITY_CANARY' };
    }
    const encoded = `${JSON.stringify(response)}\n`;
    // Exercise parsing across arbitrary stdout chunks.
    process.stdout.write(encoded.slice(0, 7));
    setTimeout(() => process.stdout.write(encoded.slice(7)), 1);
  });
}
