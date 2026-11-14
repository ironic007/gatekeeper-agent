// Proof Gatekeeper decision logic — a JS mirror of the documented trap rules.
// The gatekeeper circuit enforces the same conjunction (verified by probing):
//   APPROVE(1) iff proofVk == registeredVk AND publicBalance >= minimum
//     AND recipient == conditionRecipient AND currentBlock < expiryBlock
//     AND amount <= maxTransfer.
// PROOF_REUSED is agent-side state (seen-set), not a circuit input.
"use strict";

const REASONS = {
  APPROVE: "VALID_CONDITION",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  THRESHOLD_MISMATCH: "THRESHOLD_MISMATCH",
  PROOF_REUSED: "PROOF_REUSED",
  EXPIRED_CONDITION: "EXPIRED_CONDITION",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  AMOUNT_OVERFLOW: "AMOUNT_OVERFLOW",
};

function normHex(v) {
  if (v === undefined || v === null) return "";
  return String(v).trim().toLowerCase();
}
function toBig(v) {
  if (v === undefined || v === null || v === "") return null;
  try {
    const s = String(v).trim();
    if (s.startsWith("0x") || s.startsWith("0X")) return BigInt(s);
    return BigInt(s);
  } catch (_) { return null; }
}

// input: the task's `input` object. seenHas: (proofTxLower) => boolean
// Returns { decision: "APPROVE"|"REJECT", reason_code, checks: {...} }
function decide(input, seenHas) {
  const checks = {};
  const registeredVk = normHex(input.registered_vk);
  const proofVk = normHex(input.proof_vk);
  checks.vkMatch = registeredVk !== "" && proofVk !== "" && registeredVk === proofVk;

  const proofTx = normHex(input.proof_tx);
  checks.notReused = proofTx !== "" && !seenHas(proofTx);

  const minimum = toBig(input.minimum);
  const publicBalance = toBig(input.public_balance);
  checks.threshold = minimum !== null && publicBalance !== null && publicBalance >= minimum;

  checks.recipientMatch =
    normHex(input.recipient) !== "" &&
    normHex(input.recipient) === normHex(input.condition_recipient);

  const currentBlock = toBig(input.current_block);
  const expiryBlock = toBig(input.expiry_block);
  checks.notExpired = currentBlock !== null && expiryBlock !== null && currentBlock < expiryBlock;

  const amount = toBig(input.amount);
  const maxTransfer = toBig(input.max_transfer);
  checks.noOverflow = amount !== null && maxTransfer !== null && amount <= maxTransfer;

  // Precedence (single-fault tasks; order only matters for multi-fault):
  if (!checks.vkMatch) return { decision: "REJECT", reason_code: REASONS.VK_SUBSTITUTION, checks };
  if (!checks.notReused) return { decision: "REJECT", reason_code: REASONS.PROOF_REUSED, checks };
  if (!checks.threshold) return { decision: "REJECT", reason_code: REASONS.THRESHOLD_MISMATCH, checks };
  if (!checks.recipientMatch) return { decision: "REJECT", reason_code: REASONS.RECIPIENT_MISMATCH, checks };
  if (!checks.notExpired) return { decision: "REJECT", reason_code: REASONS.EXPIRED_CONDITION, checks };
  if (!checks.noOverflow) return { decision: "REJECT", reason_code: REASONS.AMOUNT_OVERFLOW, checks };
  return { decision: "APPROVE", reason_code: REASONS.APPROVE, checks };
}

module.exports = { decide, REASONS, normHex, toBig };
