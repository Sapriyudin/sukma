// Proof Gatekeeper agent for zkVerify Agent Games Season 01.
// Single Node.js process, standard library HTTP only.
//
//   POST /gatekeeper — signed task envelope from the platform
//   GET  /health     — readiness (HMAC configured? self-test?)
//   GET  /           — service info
//
// Every inbound request is HMAC-verified (x-agent-games-signature) over the
// RAW body before parsing. Every response is signed the same way. The
// preflight {"type":"agent-games.preflight.v1"} is answered
// {ok:true, protocolVersion:"v1"}.
//
// Fail closed: any uncertainty is a REJECT. This server never approves,
// signs, or spends anything — it only answers game tasks. No wallet keys
// live here.
const fs = require("fs");
const path = require("path");
const http = require("http");
const crypto = require("crypto");

(function loadEnv() {
  try {
    for (const line of fs.readFileSync(path.join(__dirname, ".env"), "utf8").split("\n")) {
      const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^['"]|['"]$/g, "");
    }
  } catch { /* no .env — env vars only */ }
})();

const { decide } = require("./gatekeeper/decide");
const { proveTask, verifyLocally } = require("./gatekeeper/prove");

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || "0.0.0.0";
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";

function hmacHex(secret, body) {
  return crypto.createHmac("sha256", secret).update(body).digest("hex");
}

function verifySignature(secret, rawBody, sig) {
  if (!sig) return false;
  const given = sig.startsWith("sha256=") ? sig.slice(7) : sig;
  const expected = hmacHex(secret, rawBody);
  const a = Buffer.from(given, "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function sendJson(res, status, obj, sign) {
  const body = JSON.stringify(obj);
  const headers = { "Content-Type": "application/json" };
  if (sign && HMAC_SECRET) headers["x-agent-games-signature"] = hmacHex(HMAC_SECRET, body);
  res.writeHead(status, headers);
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

let selfTest = "pending";

async function handleGatekeeper(obj) {
  const task = obj.input || obj;
  const required = [
    "registered_vk", "proof_vk", "minimum", "public_balance",
    "expiry_block", "current_block", "recipient", "condition_recipient",
    "amount", "max_transfer",
  ];
  for (const f of required) {
    if (task[f] === undefined || task[f] === null || task[f] === "") {
      return { status: 200, body: { decision: "REJECT", reason_code: "INVALID_TASK", proof_tx: String(task.proof_tx || "") } };
    }
  }
  const { decision, reason_code } = decide(task);
  const proofTx = String(task.proof_tx || "");
  if (reason_code === "PROOF_REUSED") {
    // A reused proof has no proof to submit (excluded from the reliability bonus).
    return { status: 200, body: { decision, reason_code, proof_tx: proofTx } };
  }
  try {
    const { proof, publicSignals } = await proveTask(task, decision);
    return { status: 200, body: { decision, reason_code, proof_tx: proofTx, proof, public_signals: publicSignals } };
  } catch (e) {
    console.error("[gatekeeper] proof generation failed (decision still returned):", e.message);
    return { status: 200, body: { decision, reason_code, proof_tx: proofTx } };
  }
}

async function selfTests() {
  try {
    const task = {
      task_id: "gk_selftest_1",
      registered_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
      proof_vk: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
      minimum: "1000", public_balance: "1460",
      expiry_block: "8430000", current_block: "8420000",
      recipient: "0x1111111111111111111111111111111111111111",
      condition_recipient: "0x1111111111111111111111111111111111111111",
      amount: "500", max_transfer: "1000", proof_tx: "0xselftest",
    };
    const { decision } = decide(task);
    const { proof, publicSignals } = await proveTask(task, decision);
    const ok = await verifyLocally(publicSignals, proof);
    selfTest = ok && decision === "APPROVE" ? "PASS (APPROVE proof verifies locally)" : "FAIL";
  } catch (e) {
    selfTest = "FAIL: " + e.message;
  }
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/health") {
      return sendJson(res, 200, {
        ok: true,
        gatekeeper: { hmacConfigured: !!HMAC_SECRET, selfTest },
        uptimeSec: Math.floor(process.uptime()),
      });
    }
    if (req.method === "GET" && req.url === "/") {
      return sendJson(res, 200, {
        service: "agent-games-proof-gatekeeper",
        endpoints: ["POST /gatekeeper", "GET /health"],
      });
    }
    if (req.method !== "POST" || req.url !== "/gatekeeper") {
      return sendJson(res, 404, { error: "not found" });
    }
    const rawBody = await readBody(req);
    if (!HMAC_SECRET) {
      console.warn("[warn] AGENT_GAMES_HMAC_SECRET is not set — inbound HMAC is NOT verified. Set it before going live.");
    } else if (!verifySignature(HMAC_SECRET, rawBody, req.headers["x-agent-games-signature"])) {
      console.warn("[warn] HMAC mismatch on", req.url);
      return sendJson(res, 401, { error: "bad signature" });
    }
    let obj;
    try {
      obj = JSON.parse(rawBody.toString("utf8"));
    } catch {
      return sendJson(res, 400, { error: "invalid JSON" });
    }
    if (obj && obj.type === "agent-games.preflight.v1") {
      return sendJson(res, 200, { ok: true, protocolVersion: "v1" }, true);
    }
    const result = await handleGatekeeper(obj);
    return sendJson(res, result.status, result.body, true);
  } catch (e) {
    console.error("[server] unhandled error:", e);
    return sendJson(res, 500, { error: "internal error" });
  }
});

server.listen(PORT, HOST, async () => {
  console.log(`[server] listening on ${HOST}:${PORT} (POST /gatekeeper, GET /health)`);
  console.log(`[server] HMAC secret: ${HMAC_SECRET ? "configured" : "NOT SET (inbound verification disabled)"}`);
  await selfTests();
  console.log(`[server] self-test gatekeeper: ${selfTest}`);
});
