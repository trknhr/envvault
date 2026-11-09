import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { once } from "node:events";
import { VM, createHttpHooks } from "@earendil-works/gondolin";

// Fake credentials only. The receiver never logs or echoes request headers.
let expectedToken = randomBytes(24).toString("hex");
let acceptedRequests = 0;
const receiver = createServer((request, response) => {
  const accepted = request.headers.authorization === `Bearer ${expectedToken}`;
  if (accepted) acceptedRequests++;
  response.writeHead(accepted ? 200 : 401, { "Content-Type": "text/plain" });
  response.end(accepted ? "credential accepted\n" : "credential rejected\n");
});
receiver.listen(0, "127.0.0.1");
await once(receiver, "listening");
const { port } = receiver.address();

const { httpHooks, env, secretManager } = createHttpHooks({
  allowedHosts: ["example.com"],
  // Permit only the loopback receiver below; other private targets stay blocked.
  allowedInternalHosts: ["127.0.0.1"],
  isRequestAllowed: (request) => {
    const url = new URL(request.url);
    return url.hostname !== "127.0.0.1" ||
      (url.protocol === "http:" && url.port === String(port) && url.pathname === "/");
  },
  secrets: {
    ENVVAULT_TEST_TOKEN: { hosts: ["127.0.0.1"], value: expectedToken },
  },
});

let vm;
try {
  console.log("Starting Gondolin (first use downloads the guest image)...");
  vm = await VM.create({ httpHooks, env });

  async function run(command) {
    const result = await vm.exec(command, { signal: AbortSignal.timeout(30_000) });
    assert.equal(result.exitCode, 0, "guest command failed (output withheld)");
    return result.stdout.trim();
  }

  const bootId = await run(["cat", "/proc/sys/kernel/random/boot_id"]);
  assert.equal(await run("printf 'hello from Gondolin\\n' > /tmp/gondolin-test; cat /tmp/gondolin-test; rm /tmp/gondolin-test"), "hello from Gondolin");
  console.log("PASS: Linux VM and temporary file I/O");

  await run(["curl", "--fail", "--silent", "--show-error", "--max-time", "15", "--output", "/dev/null", "https://example.com/"]);
  console.log("PASS: HTTPS to allowed example.com");

  const placeholder = await run(["printenv", "ENVVAULT_TEST_TOKEN"]);
  assert.ok(placeholder === env.ENVVAULT_TEST_TOKEN && placeholder !== expectedToken, "guest must see only the placeholder");
  console.log("PASS: guest receives a placeholder");

  // Route the guest TCP connection to Gondolin's virtual gateway. The URL/Host
  // remain 127.0.0.1, so the HTTP bridge reaches this Mac's loopback receiver.
  const authorizationHeader = ["Authorization:", "Bearer"].join(" ");
  const request = ["/bin/sh", "-c", `curl --silent --show-error --max-time 10 --output /dev/null --write-out '%{http_code}' --noproxy '*' --connect-to '127.0.0.1:${port}:192.168.127.1:${port}' -H "${authorizationHeader} $ENVVAULT_TEST_TOKEN" 'http://127.0.0.1:${port}/'`];
  assert.equal(await run(request), "200", "receiver must accept the injected token");
  assert.equal(acceptedRequests, 1);
  console.log("PASS: host injects the credential into the HTTP header");

  expectedToken = randomBytes(24).toString("hex");
  secretManager.updateSecret("ENVVAULT_TEST_TOKEN", { value: expectedToken });
  assert.equal(await run(request), "200", "receiver must accept the rotated token");
  assert.equal(acceptedRequests, 2);
  assert.equal(await run(["printenv", "ENVVAULT_TEST_TOKEN"]), placeholder);
  assert.equal(await run(["cat", "/proc/sys/kernel/random/boot_id"]), bootId);
  console.log("PASS: credential rotates without restarting the VM");

  secretManager.updateSecret("ENVVAULT_TEST_TOKEN", { hosts: ["unrelated.invalid"] });
  assert.equal(await run(request), "403", "revoked secret host must be blocked");
  assert.equal(acceptedRequests, 2, "blocked request must not reach receiver");
  console.log("PASS: secret host scope changes apply without restarting");
} finally {
  try {
    await vm?.close();
  } finally {
    receiver.closeAllConnections();
    await new Promise((resolve, reject) => receiver.close((error) => error ? reject(error) : resolve()));
  }
}
