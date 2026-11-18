'use strict';
/**
 * Proof battery for the official Gatekeeper circuit.
 * Verifies (empirically, in this repo) the circuit input-signal names and
 * field encodings recovered from the wasm input table:
 *   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
 *   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
 *   decision, taskId, salt(private)
 * Encodings: VK hashes and taskId are keccak256 values reduced mod the BN254
 * field prime; addresses are plain integers; decision 1=APPROVE, 0=REJECT.
 */
const path = require('path');
const snarkjs = require('snarkjs');
const { keccak256, keccak256Hex } = require('../lib/keccak');

const ROOT = path.join(__dirname, '..');
const WASM = path.join(ROOT, 'circuits', 'gatekeeper.wasm');
const ZKEY = path.join(ROOT, 'circuits', 'gatekeeper_final.zkey');
const VK = require(path.join(ROOT, 'circuits', 'verification_key.json'));

const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const REGISTERED_VK_HASH = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0'; // official /api/circuit-info

const modP = (x) => (BigInt(x) % FIELD_P).toString();
const hashToField = (hex) => modP(BigInt(hex));

function baseInput(overrides = {}) {
  const recipient = BigInt('0x1234567890abcdef1234567890abcdef12345678').toString();
  return Object.assign({
    registeredVkHash: hashToField(REGISTERED_VK_HASH),
    proofVkHash: hashToField(REGISTERED_VK_HASH),
    minimum: '1000',
    publicBalance: '1460',
    expiryBlock: '19842201',
    currentBlock: '19832000',
    recipient,
    conditionRecipient: recipient,
    amount: '500',
    maxTransfer: '1000',
    decision: '1',
    taskId: hashToField(keccak256Hex('gk_prooftest_1')),
    salt: '123456789',
  }, overrides);
}

const OTHER_VK = hashToField(keccak256Hex('some-other-vk'));
const OTHER_RECIPIENT = BigInt('0x9999999999999999999999999999999999999999').toString();

const CASES = [
  { name: 'valid -> APPROVE',            input: baseInput(),                                        expect: 'prove+verify' },
  { name: 'valid -> REJECT (wrong)',     input: baseInput({ decision: '0' }),                       expect: 'witness-fail' },
  { name: 'VK_SUBSTITUTION -> REJECT',   input: baseInput({ proofVkHash: OTHER_VK, decision: '0' }), expect: 'prove+verify' },
  { name: 'VK_SUBSTITUTION -> APPROVE (wrong)', input: baseInput({ proofVkHash: OTHER_VK }),       expect: 'witness-fail' },
  { name: 'THRESHOLD_MISMATCH -> REJECT', input: baseInput({ publicBalance: '900', decision: '0' }), expect: 'prove+verify' },
  { name: 'THRESHOLD_MISMATCH -> APPROVE (wrong)', input: baseInput({ publicBalance: '900' }),      expect: 'witness-fail' },
  { name: 'EXPIRED -> REJECT',           input: baseInput({ currentBlock: '19850000', decision: '0' }), expect: 'prove+verify' },
  { name: 'RECIPIENT_MISMATCH -> REJECT', input: baseInput({ conditionRecipient: OTHER_RECIPIENT, decision: '0' }), expect: 'prove+verify' },
  { name: 'AMOUNT_OVERFLOW -> REJECT',   input: baseInput({ amount: '1500', decision: '0' }),       expect: 'prove+verify' },
  { name: 'AMOUNT_OVERFLOW -> APPROVE (wrong)', input: baseInput({ amount: '1500' }),               expect: 'witness-fail' },
];

async function main() {
  // keccak self-check against the canonical empty-string vector
  const emptyHash = keccak256('').toString('hex');
  console.log('keccak256("") =', emptyHash);
  console.log('keccak vector OK:', emptyHash === 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');

  let pass = 0, fail = 0;
  for (const c of CASES) {
    let result, detail = '';
    try {
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(c.input, WASM, ZKEY);
      const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
      result = ok ? 'prove+verify' : 'prove-but-verify-FALSE';
      detail = 'publicSignals=' + JSON.stringify(publicSignals);
    } catch (e) {
      result = 'witness-fail';
      detail = String(e && e.message ? e.message : e).split('\n')[0].slice(0, 160);
    }
    const good = result === c.expect;
    good ? pass++ : fail++;
    console.log(`[${good ? 'PASS' : 'FAIL'}] ${c.name}: got=${result} expect=${c.expect} :: ${detail}`);
  }
  console.log(`\nPROOFTEST SUMMARY: ${pass} passed, ${fail} failed, ${CASES.length} total`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
