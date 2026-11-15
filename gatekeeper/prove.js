// Proof Gatekeeper — Groth16 proof generation with the official circuit.
// Circuit inputs: registeredVkHash, proofVkHash, minimum, publicBalance,
// expiryBlock, currentBlock, recipient, conditionRecipient, amount,
// maxTransfer, decision (1 = APPROVE, 0 = REJECT), taskId, salt (private).
// Public signals (13): [hash, registeredVkHash, proofVkHash, minimum,
// publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
// amount, maxTransfer, decision, taskId].
//
// taskId mapping: the envelope's task_id is a string like "gk_24_9d1";
// the circuit needs a field element, so we use keccak256(task_id UTF-8)
// mod the BN254 field prime.
const crypto = require("crypto");
const path = require("path");
const snarkjs = require("snarkjs");
const { ethers } = require("ethers");

const FIELD_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);
const WASM = path.join(__dirname, "..", "circuits", "gatekeeper.wasm");
const ZKEY = path.join(__dirname, "..", "circuits", "gatekeeper_final.zkey");
const VK = require(path.join(__dirname, "..", "circuits", "verification_key.json"));

function taskIdToField(taskId) {
  const hash = ethers.keccak256(ethers.toUtf8Bytes(String(taskId || "")));
  return (BigInt(hash) % FIELD_PRIME).toString();
}

function buildInput(task, decision) {
  return {
    registeredVkHash: String(task.registered_vk),
    proofVkHash: String(task.proof_vk),
    minimum: String(task.minimum),
    publicBalance: String(task.public_balance),
    expiryBlock: String(task.expiry_block),
    currentBlock: String(task.current_block),
    recipient: String(task.recipient),
    conditionRecipient: String(task.condition_recipient),
    amount: String(task.amount),
    maxTransfer: String(task.max_transfer),
    decision: decision === "APPROVE" ? "1" : "0",
    taskId: taskIdToField(task.task_id),
    salt: "0x" + crypto.randomBytes(32).toString("hex"),
  };
}

async function proveTask(task, decision) {
  const input = buildInput(task, decision);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  return { proof, publicSignals };
}

async function verifyLocally(publicSignals, proof) {
  return snarkjs.groth16.verify(VK, publicSignals, proof);
}

module.exports = { taskIdToField, buildInput, proveTask, verifyLocally };
