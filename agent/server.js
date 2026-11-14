// Proof Gatekeeper agent service — "ironic" entry for zkVerify Agent Games.
// Protocol (from agentgames.zkverify.io/build + official starter prompt):
//   - Platform POSTs HMAC-signed task envelopes; verify x-agent-games-signature
//     (HMAC-SHA256 hex over the RAW body) BEFORE parsing.
//   - Preflight: reply { ok: true, protocolVersion: "v1" }, signed.
//   - Task: reply { decision, reason_code, proof_tx, proof, public_signals },
//     signed with x-agent-games-signature over the raw response body.
//   - 60s hard deadline; fail closed (REJECT) on any error or uncertainty.
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { decide, normHex } = require("./lib/decide");
const { buildCircuitInput, prove, kurierConfirm } = require("./lib/circuit");

const ROOT = path.join(__dirname, "..");
const DATA_DIR = path.join(ROOT, "data");
const LOG_DIR = path.join(ROOT, "logs");
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(LOG_DIR, { recursive: true });

// --- config ---------------------------------------------------------------
function loadEnvFile(file) {
  try {
    for (const line of fs.readFileSync(file, "utf8").split("\n")) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
      if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
    }
  } catch (_) { /* optional */ }
}
loadEnvFile(path.join(ROOT, "agent.env"));

const PORT = parseInt(process.env.PORT || "8787", 10);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const KURIER_API_KEY = process.env.KURIER_API_KEY || "";
const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const SOFT_DEADLINE_MS = 52000;

function log(obj) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...obj });
  console.log(line);
  try { fs.appendFileSync(path.join(LOG_DIR, "tasks.jsonl"), line + "\n"); } catch (_) {}
}

// --- seen-set (PROOF_REUSED), persisted, scoped by mode --------------------
const SEEN_PATH = path.join(DATA_DIR, "seen.json");
let seen = {};
try { seen = JSON.parse(fs.readFileSync(SEEN_PATH, "utf8")); } catch (_) { seen = {}; }
function seenHas(mode, proofTxLower) { return Boolean(seen[`${mode}:${proofTxLower}`]); }
function seenRecord(mode, proofTxLower, taskId) {
  seen[`${mode}:${proofTxLower}`] = { taskId, at: new Date().toISOString() };
  const tmp = SEEN_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(seen, null, 1));
  fs.renameSync(tmp, SEEN_PATH);
}

// --- HMAC -------------------------------------------------------------------
function hmacHex(secret, raw) {
  return crypto.createHmac("sha256", secret).update(raw).digest("hex");
}
function verifySignature(rawBody, headerValue) {
  if (!HMAC_SECRET) return true; // bootstrap only; secret is set at registration
  if (!headerValue) return false;
  const provided = String(headerValue).trim().replace(/^sha256=/i, "").toLowerCase();
  const expected = hmacHex(HMAC_SECRET, rawBody);
  const a = Buffer.from(provided, "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function signResponse(res, bodyStr) {
  if (HMAC_SECRET) res.setHeader("x-agent-games-signature", hmacHex(HMAC_SECRET, bodyStr));
}
function sendJson(res, code, obj) {
  const bodyStr = JSON.stringify(obj);
  res.statusCode = code;
  res.setHeader("content-type", "application/json");
  signResponse(res, bodyStr);
  res.end(bodyStr);
}

// --- task handling ----------------------------------------------------------
async function handleTask(task) {
  const started = Date.now();
  const input = task.input || task.data || task;
  const mode = String(task.mode || input.mode || "competition").toLowerCase();
  const proofTx = normHex(input.proof_tx);

  const { decision, reason_code, checks } = decide(input, (tx) => seenHas(mode, tx));
  if (proofTx) seenRecord(mode, proofTx, task.task_id || null);

  let proof = null, publicSignals = null, proveError = null, kurier = null;
  try {
    const circuitInput = buildCircuitInput({ ...task, input }, decision);
    const out = await prove(circuitInput);
    proof = out.proof;
    publicSignals = out.publicSignals;
    log({ ev: "proved", task_id: task.task_id || null, decision, ms: Date.now() - started, salt: circuitInput.salt });
  } catch (e) {
    proveError = String(e && e.message ? e.message : e).slice(0, 300);
    log({ ev: "prove_failed", task_id: task.task_id || null, decision, error: proveError });
  }

  if (proof && KURIER_API_KEY) {
    const remaining = SOFT_DEADLINE_MS - (Date.now() - started) - 3000;
    if (remaining > 5000) {
      kurier = await kurierConfirm(KURIER_API_KEY, proof, publicSignals, remaining);
      log({ ev: "kurier", task_id: task.task_id || null, ...kurier });
    }
  }

  return {
    body: {
      decision,
      reason_code,
      proof_tx: input.proof_tx || null,
      proof,
      public_signals: publicSignals,
    },
    meta: { checks, proveError, kurier, ms: Date.now() - started },
  };
}

const server = http.createServer((req, res) => {
  if (req.method === "GET") {
    return sendJson(res, 200, { ok: true, protocolVersion: "v1", agent: "ironic-proof-gatekeeper" });
  }
  if (req.method !== "POST") return sendJson(res, 405, { ok: false, error: "method_not_allowed" });

  const chunks = [];
  let size = 0;
  req.on("data", (c) => {
    size += c.length;
    if (size > 2 * 1024 * 1024) { req.destroy(); return; }
    chunks.push(c);
  });
  req.on("end", async () => {
    const rawBody = Buffer.concat(chunks);
    if (!verifySignature(rawBody, req.headers["x-agent-games-signature"])) {
      log({ ev: "bad_signature", path: req.url });
      return sendJson(res, 401, { ok: false, error: "invalid_signature" });
    }
    let parsed;
    try { parsed = JSON.parse(rawBody.toString("utf8")); }
    catch (_) { return sendJson(res, 400, { ok: false, error: "invalid_json" }); }

    const isTask = parsed && (parsed.type === TASK_TYPE || (parsed.input && parsed.input.proof_tx));
    if (!isTask) {
      // Preflight / health POST: signed acknowledgement, echoing any challenge.
      const reply = { ok: true, protocolVersion: "v1" };
      if (parsed && parsed.challenge !== undefined) reply.challenge = parsed.challenge;
      if (parsed && parsed.nonce !== undefined) reply.nonce = parsed.nonce;
      if (parsed && parsed.task_id !== undefined) reply.task_id = parsed.task_id;
      log({ ev: "preflight", type: parsed && parsed.type, path: req.url });
      return sendJson(res, 200, reply);
    }

    let responded = false;
    const timer = setTimeout(() => {
      if (responded) return;
      responded = true;
      log({ ev: "soft_deadline_reject", task_id: parsed.task_id || null });
      sendJson(res, 200, {
        decision: "REJECT", reason_code: "VK_SUBSTITUTION",
        proof_tx: (parsed.input && parsed.input.proof_tx) || null, proof: null, public_signals: null,
      });
    }, SOFT_DEADLINE_MS);

    try {
      const { body, meta } = await handleTask(parsed);
      if (responded) return;
      responded = true;
      clearTimeout(timer);
      log({ ev: "answered", task_id: parsed.task_id || null, ...body && { decision: body.decision, reason_code: body.reason_code }, ...meta });
      sendJson(res, 200, body);
    } catch (e) {
      if (responded) return;
      responded = true;
      clearTimeout(timer);
      log({ ev: "handler_error", task_id: parsed.task_id || null, error: String(e && e.message || e).slice(0, 300) });
      sendJson(res, 200, {
        decision: "REJECT", reason_code: "VK_SUBSTITUTION",
        proof_tx: (parsed.input && parsed.input.proof_tx) || null, proof: null, public_signals: null,
      });
    }
  });
});

const HOST = process.env.HOST || "127.0.0.1";
server.listen(PORT, HOST, () => {
  log({ ev: "listening", port: PORT, hmacConfigured: Boolean(HMAC_SECRET), kurierConfigured: Boolean(KURIER_API_KEY) });
});
