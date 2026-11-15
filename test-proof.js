// Local Gatekeeper proof test — sample scenario from the official field guide.
// Valid: balance 1460 >= min 1000, amount 500 <= cap 1000, recipient matches,
// expiry 8430000 > current 8420000, proof VK == registered VK.
const snarkjs = require("snarkjs");
const crypto = require("crypto");

const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const P = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

function keccakModP(buf) {
  // keccak256 via Node's built-in? Node crypto has no keccak; use a tiny fallback:
  // sha3-256 is NOT keccak, but for a local smoke test any deterministic
  // field mapping works — the platform check happens in practice tasks.
  const h = crypto.createHash("sha3-256").update(buf).digest("hex");
  return (BigInt("0x" + h) % P).toString();
}

async function main() {
  const base = {
    registeredVkHash: VK_HASH,
    proofVkHash: VK_HASH,
    minimum: "1000",
    publicBalance: "1460",
    expiryBlock: "8430000",
    currentBlock: "8420000",
    recipient: "0xDe42000000000000000000000000000000009f01",
    conditionRecipient: "0xDe42000000000000000000000000000000009f01",
    amount: "500",
    maxTransfer: "1000",
    taskId: keccakModP(Buffer.from("gk_24_9d1", "utf8")),
    salt: "0x" + crypto.randomBytes(32).toString("hex"),
  };
  const vk = require("./circuits/verification_key.json");

  // 1. Valid APPROVE
  let t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    { ...base, decision: "1" },
    "circuits/gatekeeper.wasm",
    "circuits/gatekeeper_final.zkey"
  );
  console.log("APPROVE proof generated in", Date.now() - t0, "ms");
  console.log("publicSignals:", publicSignals.length, "first:", publicSignals[0].slice(0, 20) + "...");
  const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
  console.log("APPROVE verifies locally:", ok);

  // 2. Dishonest APPROVE on recipient mismatch must be unprovable
  try {
    await snarkjs.groth16.fullProve(
      { ...base, decision: "1", conditionRecipient: "0x0000000000000000000000000000000000000001" },
      "circuits/gatekeeper.wasm",
      "circuits/gatekeeper_final.zkey"
    );
    console.log("TRAP TEST FAILED: dishonest APPROVE produced a proof!");
  } catch (e) {
    console.log("TRAP TEST OK: dishonest APPROVE unprovable:", String(e.message).slice(0, 80));
  }

  // 3. REJECT on the same trap input must prove fine
  const r = await snarkjs.groth16.fullProve(
    { ...base, decision: "0", conditionRecipient: "0x0000000000000000000000000000000000000001" },
    "circuits/gatekeeper.wasm",
    "circuits/gatekeeper_final.zkey"
  );
  const okR = await snarkjs.groth16.verify(vk, r.publicSignals, r.proof);
  console.log("REJECT on trap verifies locally:", okR);
  console.log("ALL LOCAL PROOF TESTS DONE");
}
main().catch((e) => { console.error("FATAL", e.message); process.exit(1); });
