'use strict';
// Decision logic + Groth16 proof generation for Proof Gatekeeper.
// Circuit input signals (verified empirically against the official artifacts
// in test/prooftest.js): registeredVkHash, proofVkHash, minimum,
// publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
// amount, maxTransfer, decision, taskId, salt(private).
// Encodings: VK hashes and taskId = keccak256 values reduced mod the BN254
// field prime; addresses = plain integers; decision 1=APPROVE, 0=REJECT.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const snarkjs = require('snarkjs');
const { keccak256Hex } = require('./keccak');

const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const ROOT = path.join(__dirname, '..');
const WASM = path.join(ROOT, 'circuits', 'gatekeeper.wasm');
const ZKEY = path.join(ROOT, 'circuits', 'gatekeeper_final.zkey');
const SEEN_FILE = path.join(ROOT, 'data', 'seen.json');

function toFieldFromHashHex(v) {
  // Accept a 0x-prefixed hash (full or already a field value) -> reduce mod p.
  return (BigInt(v) % FIELD_P).toString();
}
function toFieldFromNumberLike(v) {
  // Amounts / blocks arrive as decimal strings or numbers in the task envelope.
  return BigInt(v).toString();
}
function addressToField(v) {
  // Plain integer encoding (0x address or decimal string).
  return BigInt(v).toString();
}
function taskIdToField(taskId) {
  // ASSUMPTION (not documented officially): taskId enters the circuit as
  // keccak256(task_id string) reduced mod p. If the platform already sends a
  // numeric/hex task id, use it directly.
  const s = String(taskId);
  if (/^0x[0-9a-fA-F]+$/.test(s)) return (BigInt(s) % FIELD_P).toString();
  if (/^[0-9]+$/.test(s)) return (BigInt(s) % FIELD_P).toString();
  return (BigInt(keccak256Hex(s)) % FIELD_P).toString();
}

// ---- persistent seen-set for proof_tx (PROOF_REUSED detection) ----
function loadSeen() {
  try {
    const arr = JSON.parse(fs.readFileSync(SEEN_FILE, 'utf8'));
    return new Set(Array.isArray(arr) ? arr : []);
  } catch { return new Set(); }
}
function saveSeen(set) {
  try {
    fs.mkdirSync(path.dirname(SEEN_FILE), { recursive: true });
    fs.writeFileSync(SEEN_FILE, JSON.stringify([...set], null, 2));
  } catch (e) { console.error('seen-set save failed:', e.message); }
}

/**
 * Evaluate a gatekeeper task input. Pure/deterministic.
 * Returns { decision, reason_code, reused }.
 */
function evaluate(input, seen) {
  const eqAddr = (a, b) => BigInt(a) === BigInt(b);
  const vkEqual = (() => {
    if (String(input.proof_vk).toLowerCase() === String(input.registered_vk).toLowerCase()) return true;
    try { return BigInt(input.proof_vk) === BigInt(input.registered_vk); } catch { return false; }
  })();
  if (!vkEqual) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', reused: false };
  }
  if (BigInt(input.public_balance) < BigInt(input.minimum)) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH', reused: false };
  }
  if (input.proof_tx && seen.has(String(input.proof_tx))) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED', reused: true };
  }
  if (BigInt(input.current_block) > BigInt(input.expiry_block)) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', reused: false };
  }
  if (!eqAddr(input.recipient, input.condition_recipient)) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH', reused: false };
  }
  if (BigInt(input.amount) > BigInt(input.max_transfer)) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW', reused: false };
  }
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION', reused: false };
}

async function generateProof(task, decision) {
  const input = task.input;
  const circuitInput = {
    registeredVkHash: toFieldFromHashHex(input.registered_vk),
    proofVkHash: toFieldFromHashHex(input.proof_vk),
    minimum: toFieldFromNumberLike(input.minimum),
    publicBalance: toFieldFromNumberLike(input.public_balance),
    expiryBlock: toFieldFromNumberLike(input.expiry_block),
    currentBlock: toFieldFromNumberLike(input.current_block),
    recipient: addressToField(input.recipient),
    conditionRecipient: addressToField(input.condition_recipient),
    amount: toFieldFromNumberLike(input.amount),
    maxTransfer: toFieldFromNumberLike(input.max_transfer),
    decision: decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdToField(task.task_id),
    salt: (BigInt('0x' + crypto.randomBytes(31).toString('hex')) % FIELD_P).toString(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM, ZKEY);
  return { proof, publicSignals };
}

module.exports = { evaluate, generateProof, loadSeen, saveSeen, FIELD_P };
