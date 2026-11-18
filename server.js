'use strict';
/**
 * Proof Gatekeeper agent — zkVerify Agent Games Season 01.
 * Node.js stdlib only (http + crypto); snarkjs is the sole dependency.
 *
 * Protocol (official sources: agentgames.zkverify.io/build, /rules,
 * /events/proof-gatekeeper, starter prompt embedded in /build):
 *  - Platform POSTs signed envelopes to the registered endpoint.
 *  - Verify HMAC-SHA256 over the RAW body vs the x-agent-games-signature
 *    header BEFORE parsing JSON. Fail closed on any mismatch.
 *  - Preflight envelope { type:"agent-games.preflight.v1", ... } must be
 *    answered with { ok:true, protocolVersion:"v1" }, signed.
 *  - Gatekeeper task { type:"agent-games.proof-gatekeeper.v1", task_id,
 *    input:{ registered_vk, proof_vk, minimum, public_balance, expiry_block,
 *    current_block, recipient, condition_recipient, amount, max_transfer,
 *    proof_tx } } is answered with a signed JSON
 *    { decision, reason_code, proof_tx, proof, public_signals }.
 *  - Every response is signed: x-agent-games-signature = HMAC-SHA256 hex of
 *    the raw response body with AGENT_GAMES_HMAC_SECRET.
 *
 * UNVERIFIED DETAILS (no public official source found — see README):
 *  - exact byte format of the signature header value (bare hex assumed;
 *    a "sha256=" prefix is NOT stripped/added),
 *  - whether the platform's health check hits GET /health or the preflight.
 */
const http = require('http');
const crypto = require('crypto');
const { evaluate, generateProof, loadSeen, saveSeen } = require('./lib/gatekeeper');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const seen = loadSeen();

function hmacHex(secret, data) {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}
function signaturesMatch(expectedHex, given) {
  if (!given || typeof given !== 'string') return false;
  const a = Buffer.from(expectedHex, 'utf8');
  const b = Buffer.from(given.trim(), 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function sendSigned(res, status, obj) {
  const body = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  if (SECRET) headers['x-agent-games-signature'] = hmacHex(SECRET, body);
  res.writeHead(status, headers);
  res.end(body);
}

async function handleTask(task, res) {
  const input = task && task.input;
  if (!input) {
    return sendSigned(res, 200, { decision: 'REJECT', reason_code: 'MALFORMED_TASK' });
  }
  const verdict = evaluate(input, seen);
  const response = {
    decision: verdict.decision,
    reason_code: verdict.reason_code,
    proof_tx: input.proof_tx || null,
  };
  // Record the proof reference AFTER evaluation so the current task is not
  // flagged as its own reuse; subsequent tasks with the same proof_tx are.
  if (input.proof_tx) { seen.add(String(input.proof_tx)); saveSeen(seen); }

  // PROOF_REUSED is excluded from the proof requirement by the official
  // scoring notes; every other provable decision carries a Groth16 proof.
  if (!verdict.reused) {
    try {
      const { proof, publicSignals } = await generateProof(task, verdict.decision);
      response.proof = proof;
      response.public_signals = publicSignals;
    } catch (e) {
      // Fail closed: never APPROVE without a proof. If proving the (correct)
      // decision failed unexpectedly, downgrade to a bare REJECT.
      console.error('proof generation failed:', e.message);
      if (response.decision === 'APPROVE') {
        response.decision = 'REJECT';
        response.reason_code = 'PROOF_GENERATION_FAILED';
      }
    }
  }
  return sendSigned(res, 200, response);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');

  if (req.method === 'GET' && url.pathname === '/health') {
    return sendSigned(res, 200, {
      ok: true,
      service: 'proof-gatekeeper',
      protocolVersion: 'v1',
      hmacConfigured: Boolean(SECRET),
      seenProofs: seen.size,
    });
  }

  if (req.method === 'POST' && (url.pathname === '/gatekeeper' || url.pathname === '/agent')) {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const raw = Buffer.concat(chunks);
      // Fail closed: no secret configured -> authenticate nothing.
      if (!SECRET) return sendSigned(res, 401, { ok: false, error: 'hmac_not_configured' });
      const given = req.headers['x-agent-games-signature'];
      if (!signaturesMatch(hmacHex(SECRET, raw), given)) {
        return sendSigned(res, 401, { ok: false, error: 'invalid_signature' });
      }
      let msg;
      try { msg = JSON.parse(raw.toString('utf8')); }
      catch { return sendSigned(res, 400, { ok: false, error: 'invalid_json' }); }

      if (msg.type === 'agent-games.preflight.v1') {
        return sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
      }
      if (msg.type === 'agent-games.proof-gatekeeper.v1' || msg.input) {
        try { return await handleTask(msg, res); }
        catch (e) {
          console.error('task handling failed:', e);
          return sendSigned(res, 200, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR' });
        }
      }
      return sendSigned(res, 400, { ok: false, error: 'unknown_envelope_type' });
    });
    return;
  }

  return sendSigned(res, 404, { ok: false, error: 'not_found' });
});

server.listen(PORT, () => {
  console.log(`proof-gatekeeper listening on :${PORT} (hmacConfigured=${Boolean(SECRET)}, seenProofs=${seen.size})`);
});
