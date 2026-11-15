// Proof Gatekeeper — deterministic decision logic for zkVerify Agent Games.
// The Groth16 circuit is the referee: it enforces that the decision matches
// the correct evaluation of the inputs, so this module must implement
// EXACTLY the circuit's checks. A wrong decision cannot be proven —
// witness generation fails — which is the whole point of the track.
//
// Checks, first failing trap wins (reason_code = trap name):
//   VK_SUBSTITUTION   proof_vk != registered_vk
//   PROOF_REUSED      proof_tx already seen under a DIFFERENT task_id
//   THRESHOLD_MISMATCH public_balance < minimum
//   EXPIRED_CONDITION current_block >= expiry_block (STRICT: equal is expired)
//   RECIPIENT_MISMATCH recipient != condition_recipient (case-insensitive)
//   AMOUNT_OVERFLOW   amount > max_transfer
//   else VALID_CONDITION -> APPROVE
//
// Boundaries: balance == minimum is valid, amount == max_transfer is valid.
const seenProofTx = new Map(); // proof_tx (lowercased) -> task_id

function decide(input) {
  const registeredVk = String(input.registered_vk || "").toLowerCase();
  const proofVk = String(input.proof_vk || "").toLowerCase();
  const minimum = BigInt(input.minimum);
  const publicBalance = BigInt(input.public_balance);
  const expiryBlock = BigInt(input.expiry_block);
  const currentBlock = BigInt(input.current_block);
  const recipient = String(input.recipient || "").toLowerCase();
  const conditionRecipient = String(input.condition_recipient || "").toLowerCase();
  const amount = BigInt(input.amount);
  const maxTransfer = BigInt(input.max_transfer);
  const proofTx = String(input.proof_tx || "").toLowerCase();
  const taskId = String(input.task_id || "");

  if (proofVk !== registeredVk) return { decision: "REJECT", reason_code: "VK_SUBSTITUTION" };

  if (proofTx) {
    const prevTask = seenProofTx.get(proofTx);
    if (prevTask !== undefined && prevTask !== taskId) {
      return { decision: "REJECT", reason_code: "PROOF_REUSED" };
    }
    if (prevTask === undefined) seenProofTx.set(proofTx, taskId);
  }

  if (publicBalance < minimum) return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" };
  if (currentBlock >= expiryBlock) return { decision: "REJECT", reason_code: "EXPIRED_CONDITION" };
  if (recipient !== conditionRecipient) return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" };
  if (amount > maxTransfer) return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW" };

  return { decision: "APPROVE", reason_code: "VALID_CONDITION" };
}

module.exports = { decide, seenProofTx };
