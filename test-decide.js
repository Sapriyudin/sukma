// Unit tests for the Gatekeeper decision logic — all 7 trap varieties
// plus the boundary cases. No proofs involved, runs in milliseconds.
const { decide } = require("./gatekeeper/decide");

const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ADDR = "0xDe42000000000000000000000000000000009f01";

function base(over = {}) {
  return {
    task_id: "gk_test_1",
    registered_vk: VK, proof_vk: VK,
    minimum: "1000", public_balance: "1460",
    expiry_block: "8430000", current_block: "8420000",
    recipient: ADDR, condition_recipient: ADDR,
    amount: "500", max_transfer: "1000",
    proof_tx: "0xtest" + Math.random().toString(16).slice(2, 8),
    ...over,
  };
}

const cases = [
  ["valid", base(), "APPROVE", "VALID_CONDITION"],
  ["vk substitution", base({ proof_vk: "0x00000000000000000000000000000000000000000000000000000000000000aa" }), "REJECT", "VK_SUBSTITUTION"],
  ["threshold", base({ public_balance: "900" }), "REJECT", "THRESHOLD_MISMATCH"],
  ["threshold boundary (balance == minimum)", base({ public_balance: "1000" }), "APPROVE", "VALID_CONDITION"],
  ["expired", base({ current_block: "8430001" }), "REJECT", "EXPIRED_CONDITION"],
  ["expired boundary (current == expiry)", base({ current_block: "8430000" }), "REJECT", "EXPIRED_CONDITION"],
  ["recipient", base({ condition_recipient: "0x0000000000000000000000000000000000000001" }), "REJECT", "RECIPIENT_MISMATCH"],
  ["amount", base({ amount: "1500" }), "REJECT", "AMOUNT_OVERFLOW"],
  ["amount boundary (amount == max)", base({ amount: "1000" }), "APPROVE", "VALID_CONDITION"],
];

// proof reuse: same proof_tx under a different task_id
const t1 = base({ task_id: "gk_reuse_a", proof_tx: "0xreuse1" });
const t2 = base({ task_id: "gk_reuse_b", proof_tx: "0xreuse1" });
const t3 = base({ task_id: "gk_reuse_a", proof_tx: "0xreuse1" }); // platform retry: same task_id, NOT reuse
cases.push(["reuse setup (first sight)", t1, "APPROVE", "VALID_CONDITION"]);
cases.push(["proof reused (different task)", t2, "REJECT", "PROOF_REUSED"]);
cases.push(["same task retry (not reuse)", t3, "APPROVE", "VALID_CONDITION"]);

let fail = 0;
for (const [name, input, wantD, wantR] of cases) {
  const { decision, reason_code } = decide(input);
  const ok = decision === wantD && reason_code === wantR;
  if (!ok) fail++;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}: got ${decision}/${reason_code}, want ${wantD}/${wantR}`);
}
console.log(fail === 0 ? "ALL DECIDE TESTS PASSED" : `${fail} TESTS FAILED`);
process.exit(fail === 0 ? 0 : 1);
