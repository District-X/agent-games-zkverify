'use strict';
/**
 * Local endpoint self-test. Starts server.js with a LOCAL TEST secret,
 * sends signed envelopes (official sample shape + trap variants), and checks
 * decisions, reason codes, response signatures, and proof validity.
 * Also checks: bad signature -> 401, missing signature -> 401.
 */
const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');

const ROOT = path.join(__dirname, '..');
const PORT = 3417;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = 'local-test-secret-do-not-use-in-production';
const VK = require(path.join(ROOT, 'circuits', 'verification_key.json'));
const REGISTERED_VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const OTHER_VK = '0x13aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

const sign = (body) => crypto.createHmac('sha256', SECRET).update(body).digest('hex');
let passed = 0, failed = 0;
function check(name, cond, detail = '') {
  cond ? passed++ : failed++;
  console.log(`[${cond ? 'PASS' : 'FAIL'}] ${name}${detail ? ' :: ' + detail : ''}`);
}

function baseTask(overrides = {}, inputOverrides = {}) {
  return Object.assign({
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'gk_selftest_' + Math.random().toString(36).slice(2, 8),
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: Object.assign({
      registered_vk: REGISTERED_VK,
      proof_vk: REGISTERED_VK,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: '0x1234567890abcdef1234567890abcdef12345678',
      condition_recipient: '0x1234567890abcdef1234567890abcdef12345678',
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0x' + crypto.randomBytes(32).toString('hex'),
    }, inputOverrides),
  }, overrides);
}

async function post(pathname, obj, { signature } = {}) {
  const body = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  if (signature !== null) headers['x-agent-games-signature'] = signature !== undefined ? signature : sign(body);
  const res = await fetch(BASE + pathname, { method: 'POST', headers, body });
  const text = await res.text();
  return { status: res.status, text, json: JSON.parse(text), sig: res.headers.get('x-agent-games-signature') };
}
const responseSigOk = (r) => r.sig === sign(r.text);

async function waitHealth(proc) {
  for (let i = 0; i < 50; i++) {
    try { const r = await fetch(BASE + '/health'); if (r.ok) return; } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('server did not come up');
}

async function main() {
  // fresh seen-set so reuse test is deterministic
  fs.rmSync(path.join(ROOT, 'data', 'seen.json'), { force: true });
  const proc = spawn('node', ['server.js'], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  proc.stderr.on('data', (d) => process.stderr.write('[server] ' + d));
  try {
    await waitHealth(proc);

    const health = await (await fetch(BASE + '/health')).json();
    check('GET /health', health.ok === true && health.hmacConfigured === true, JSON.stringify(health));

    const pre = await post('/agent', { type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' });
    check('preflight -> {ok:true, protocolVersion:"v1"}', pre.status === 200 && pre.json.ok === true && pre.json.protocolVersion === 'v1');
    check('preflight response signature valid', responseSigOk(pre));

    const valid = baseTask();
    const rValid = await post('/gatekeeper', valid);
    check('valid task -> APPROVE/VALID_CONDITION', rValid.json.decision === 'APPROVE' && rValid.json.reason_code === 'VALID_CONDITION', JSON.stringify({ d: rValid.json.decision, r: rValid.json.reason_code }));
    check('valid task response signature valid', responseSigOk(rValid));
    check('valid task carries proof + public_signals', Boolean(rValid.json.proof) && Array.isArray(rValid.json.public_signals) && rValid.json.public_signals.length === 13);
    const vOk = await snarkjs.groth16.verify(VK, rValid.json.public_signals, rValid.json.proof);
    check('valid task proof verifies against official VK', vOk === true);

    const cases = [
      ['VK_SUBSTITUTION', { proof_vk: OTHER_VK }],
      ['THRESHOLD_MISMATCH', { public_balance: '900' }],
      ['EXPIRED_CONDITION', { current_block: 8430001 }],
      ['RECIPIENT_MISMATCH', { condition_recipient: '0x9999999999999999999999999999999999999999' }],
      ['AMOUNT_OVERFLOW', { amount: '1500' }],
    ];
    for (const [reason, ov] of cases) {
      const r = await post('/gatekeeper', baseTask({}, ov));
      const okDecision = r.json.decision === 'REJECT' && r.json.reason_code === reason;
      let proofOk = false;
      if (r.json.proof) proofOk = await snarkjs.groth16.verify(VK, r.json.public_signals, r.json.proof);
      check(`trap ${reason} -> REJECT + verifying proof`, okDecision && proofOk && responseSigOk(r), `decision=${r.json.decision} reason=${r.json.reason_code} proofVerifies=${proofOk}`);
    }

    const rReuse = await post('/gatekeeper', valid);
    check('PROOF_REUSED -> REJECT, no proof attached', rReuse.json.decision === 'REJECT' && rReuse.json.reason_code === 'PROOF_REUSED' && !rReuse.json.proof, JSON.stringify({ d: rReuse.json.decision, r: rReuse.json.reason_code }));

    const rBad = await post('/gatekeeper', baseTask(), { signature: 'deadbeef'.repeat(8) });
    check('bad signature -> 401', rBad.status === 401, 'status=' + rBad.status);
    const rNone = await post('/gatekeeper', baseTask(), { signature: null });
    check('missing signature -> 401', rNone.status === 401, 'status=' + rNone.status);
  } finally {
    proc.kill('SIGTERM');
  }
  console.log(`\nSELFTEST SUMMARY: ${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
