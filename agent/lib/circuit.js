// Circuit input building + Groth16 proving + Kurier submission for the
// gatekeeper circuit. Input signal names and semantics were reverse-engineered
// from the official artifacts (see probes in agent/probe*.js):
//   inputs (13): taskId, registeredVkHash, proofVkHash, minimum, publicBalance,
//     expiryBlock, currentBlock, recipient, conditionRecipient, amount,
//     maxTransfer, decision (1=APPROVE, 0=REJECT), salt (private, agent-chosen)
//   public signals: [commitment, registeredVkHash, proofVkHash, minimum,
//     publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
//     amount, maxTransfer, decision, taskId]
// Encodings: decimal strings pass through; hex hashes/addresses become
// BigInt mod p; a non-numeric taskId is keccak256(taskId) mod p.
"use strict";
const path = require("path");
const crypto = require("crypto");
const snarkjs = require("snarkjs");
const { keccak256 } = require("./keccak");

const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const CIRCUITS_DIR = path.join(__dirname, "..", "..", "circuits");
const WASM_PATH = path.join(CIRCUITS_DIR, "gatekeeper.wasm");
const ZKEY_PATH = path.join(CIRCUITS_DIR, "gatekeeper_final.zkey");
const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

function fieldFromHex(hex) {
  const v = BigInt(hex);
  return (v % FIELD_P).toString();
}
function fieldFromTaskId(taskId) {
  const s = String(taskId);
  if (/^\d+$/.test(s)) return (BigInt(s) % FIELD_P).toString();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return fieldFromHex(s);
  const h = BigInt("0x" + keccak256(s).toString("hex"));
  return (h % FIELD_P).toString();
}
function fieldFromDecimal(v) {
  return (BigInt(String(v)) % FIELD_P).toString();
}
function randomSalt() {
  const b = crypto.randomBytes(31); // < 2^248 < p
  return BigInt("0x" + b.toString("hex")).toString();
}

function buildCircuitInput(task, decision) {
  const input = task.input || task;
  return {
    taskId: fieldFromTaskId(task.task_id),
    registeredVkHash: fieldFromHex(String(input.registered_vk)),
    proofVkHash: fieldFromHex(String(input.proof_vk)),
    minimum: fieldFromDecimal(input.minimum),
    publicBalance: fieldFromDecimal(input.public_balance),
    expiryBlock: fieldFromDecimal(input.expiry_block),
    currentBlock: fieldFromDecimal(input.current_block),
    recipient: fieldFromHex(String(input.recipient)),
    conditionRecipient: fieldFromHex(String(input.condition_recipient)),
    amount: fieldFromDecimal(input.amount),
    maxTransfer: fieldFromDecimal(input.max_transfer),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: randomSalt(),
  };
}

async function prove(circuitInput) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM_PATH, ZKEY_PATH);
  return { proof, publicSignals };
}

// --- Kurier ---------------------------------------------------------------
const KURIER_BASE = process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1";

async function kurierSubmitProof(apiKey, proof, publicSignals, timeoutMs) {
  const params = {
    proofType: "groth16",
    vkRegistered: true,
    proofOptions: { library: "snarkjs", curve: "bn254" },
    proofData: { proof, publicSignals, vk: VK_HASH },
  };
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${KURIER_BASE}/submit-proof/${apiKey}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(params),
      signal: ctrl.signal,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`kurier submit HTTP ${res.status}: ${JSON.stringify(data).slice(0, 200)}`);
    return data; // { jobId, ... }
  } finally { clearTimeout(t); }
}

async function kurierJobStatus(apiKey, jobId, timeoutMs) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${KURIER_BASE}/job-status/${apiKey}/${jobId}`, { signal: ctrl.signal });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`kurier status HTTP ${res.status}`);
    return data; // { status, ... }
  } finally { clearTimeout(t); }
}

// Submit and poll until Finalized/Failed or the budget runs out.
// Returns { jobId, status } — never throws.
async function kurierConfirm(apiKey, proof, publicSignals, budgetMs) {
  const started = Date.now();
  try {
    const sub = await kurierSubmitProof(apiKey, proof, publicSignals, Math.min(15000, budgetMs));
    const jobId = sub.jobId || sub.job_id || (sub.data && sub.data.jobId);
    if (!jobId) return { jobId: null, status: "no-job-id", raw: sub };
    let status = sub.status || "Queued";
    while (Date.now() - started < budgetMs) {
      if (status === "Finalized" || status === "Failed") break;
      await new Promise((r) => setTimeout(r, 2500));
      const st = await kurierJobStatus(apiKey, jobId, 8000);
      if (st.status) status = st.status;
    }
    return { jobId, status };
  } catch (e) {
    return { jobId: null, status: "error", error: String(e.message || e).slice(0, 200) };
  }
}

module.exports = { buildCircuitInput, prove, kurierConfirm, VK_HASH, FIELD_P };
