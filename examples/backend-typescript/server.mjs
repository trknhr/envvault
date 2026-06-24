import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";

const jwks = JSON.parse(fs.readFileSync(process.env.JWKS_FILE ?? "credlease-jwks.json", "utf8"));
const issuer = process.env.ISSUER ?? "";
const resource = process.env.RESOURCE ?? "http://127.0.0.1:8080";
const completeURL = process.env.COMPLETE_URL ?? `${resource}/auth/credlease/complete`;
const postLoginURL = process.env.POST_LOGIN_URL ?? `${resource}/`;
const replay = new Set();
const codes = new Map();

function json(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(body));
}

function fail(res, status, message) {
  res.writeHead(status, { "Cache-Control": "no-store" });
  res.end(message);
}

function bearer(req) {
  const value = req.headers.authorization ?? "";
  if (!value.startsWith("Bearer ")) return "";
  const token = value.slice("Bearer ".length).trim();
  return /\s/.test(token) ? "" : token;
}

function verifyCredleaseJWT(token, purpose, requiredScope) {
  const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
  if (!encodedHeader || !encodedPayload || !encodedSignature) throw new Error("invalid token");
  const header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString("utf8"));
  const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));
  const key = jwks.keys.find((candidate) => candidate.kid === header.kid);
  if (!key) throw new Error("unknown kid");
  const publicKey = crypto.createPublicKey({ key, format: "jwk" });
  const ok = crypto.verify(
    "RSA-SHA256",
    Buffer.from(`${encodedHeader}.${encodedPayload}`),
    publicKey,
    Buffer.from(encodedSignature, "base64url"),
  );
  if (!ok) throw new Error("bad signature");
  const now = Math.floor(Date.now() / 1000);
  if (issuer && payload.iss !== issuer) throw new Error("issuer mismatch");
  if (!payload.exp || payload.exp <= now) throw new Error("expired");
  if (payload.credlease_resource !== resource) throw new Error("resource mismatch");
  if (payload.credlease_purpose !== purpose) throw new Error("purpose mismatch");
  const scopes = String(payload.scope ?? "").split(/\s+/).filter(Boolean);
  if (!scopes.includes(requiredScope)) throw new Error("scope missing");
  return payload;
}

function handleRead(req, res) {
  try {
    const claims = verifyCredleaseJWT(bearer(req), "process", "document:read");
    json(res, 200, {
      ok: true,
      operation: "read",
      profile: claims.credlease_profile,
      session_id: claims.credlease_session_id,
    });
  } catch {
    fail(res, 401, "credential not authorized");
  }
}

function handleExchange(req, res) {
  try {
    const claims = verifyCredleaseJWT(bearer(req), "browser-bootstrap", "browser:session:create");
    const sessionID = claims.credlease_session_id;
    if (!sessionID || replay.has(sessionID)) throw new Error("replay");
    replay.add(sessionID);
    const code = crypto.randomBytes(32).toString("base64url");
    codes.set(code, { claims, expiresAt: Date.now() + 30_000 });
    const launch = new URL(completeURL);
    launch.searchParams.set("code", code);
    json(res, 201, { launch_url: launch.toString(), expires_at: new Date(Date.now() + 30_000).toISOString() });
  } catch {
    fail(res, 401, "browser session exchange failed");
  }
}

function handleComplete(req, res) {
  const url = new URL(req.url, resource);
  const code = url.searchParams.get("code") ?? "";
  const entry = codes.get(code);
  codes.delete(code);
  if (!entry || entry.expiresAt <= Date.now()) {
    fail(res, 410, "browser session complete failed");
    return;
  }
  res.writeHead(303, {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "Set-Cookie": "credlease_admin_session=local-example; HttpOnly; SameSite=Lax; Path=/",
    Location: postLoginURL,
  });
  res.end();
}

http
  .createServer((req, res) => {
    if (req.method === "GET" && req.url === "/documents/read") return handleRead(req, res);
    if (req.method === "POST" && req.url?.startsWith("/auth/credlease/browser-sessions")) return handleExchange(req, res);
    if (req.method === "GET" && req.url?.startsWith("/auth/credlease/complete")) return handleComplete(req, res);
    fail(res, 404, "not found");
  })
  .listen(new URL(resource).port || 8080);
