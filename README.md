# Proof Gatekeeper Agent — zkVerify Agent Games Season 01

A Node.js agent for the **Proof Gatekeeper** track of the zkVerify Agent Games
(agentgames.zkverify.io). The platform POSTs signed transfer-decision tasks to
this endpoint; the agent answers APPROVE/REJECT with a reason code and a
Groth16 proof (BN254, generated locally with snarkjs from the official
circuit) that the platform re-verifies against its own registered VK.

- No framework: Node stdlib `http` + `crypto` only. Sole dependency: `snarkjs`.
- Fail closed everywhere: bad/missing HMAC → 401; no secret configured → 401;
  any internal error or proof failure → REJECT, never a bare APPROVE.

## Endpoints

| Route | Purpose |
|---|---|
| `GET /health` | `{ ok, service, protocolVersion, hmacConfigured, seenProofs }` |
| `POST /gatekeeper` | Gatekeeper tasks and preflight envelopes |
| `POST /agent` | Alias of `/gatekeeper` (register whichever path you deploy) |

## Protocol (as implemented)

Sources: official `/build` page **including the starter prompt embedded in
it**, `/events/proof-gatekeeper`, `/rules`, and `GET /api/circuit-info`
(all read 2026-11-18).

- **Inbound auth:** HMAC-SHA256 over the *raw* request body, compared
  (timing-safe) to the `x-agent-games-signature` header *before* JSON parsing.
- **Preflight:** envelope `{ "type": "agent-games.preflight.v1", ... }` →
  respond `{ "ok": true, "protocolVersion": "v1" }`, signed.
- **Task:** `{ "type": "agent-games.proof-gatekeeper.v1", "task_id", "mode",
  "issued_at", "deadline_at", "input": { registered_vk, proof_vk, minimum,
  public_balance, expiry_block, current_block, recipient,
  condition_recipient, amount, max_transfer, proof_tx } }`
- **Response:** signed JSON
  `{ decision, reason_code, proof_tx, proof, public_signals }`
  with `x-agent-games-signature` = HMAC-SHA256 hex of the raw response body.
  (`proof`/`public_signals` follow the official starter prompt's response
  spec `{ decision, reason_code, proof, public_signals }`; `proof_tx` echoes
  the event page's sample response. For `PROOF_REUSED` no proof is attached —
  the official scoring notes exclude reused-proof tasks from the proof
  requirement, and the circuit cannot prove a rejection of an otherwise-valid
  condition.)
- **Decisions:** APPROVE only if every check passes; otherwise REJECT with
  `VK_SUBSTITUTION`, `THRESHOLD_MISMATCH`, `PROOF_REUSED`,
  `EXPIRED_CONDITION`, `RECIPIENT_MISMATCH`, or `AMOUNT_OVERFLOW`.
  Seen `proof_tx` values persist in `data/seen.json`.

## Circuit

Official artifacts (from `GET /api/circuit-info`, network `mainnet`):

- vkHash: `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- `circuits/gatekeeper.wasm` (1,755,820 bytes, sha256 `be00aefe…64f`)
- `circuits/gatekeeper_final.zkey` (309,750 bytes, sha256 `adfe95a4…f80d`)
- `circuits/verification_key.json` exported from the zkey with snarkjs
  (groth16, bn128, 13 public signals).

Input signals (recovered from the wasm input table and **verified
empirically** by `test/prooftest.js`): `registeredVkHash, proofVkHash,
minimum, publicBalance, expiryBlock, currentBlock, recipient,
conditionRecipient, amount, maxTransfer, decision, taskId, salt` (private).
Encodings: VK hashes and taskId are keccak256 values reduced mod the BN254
field prime; addresses are plain integers; `decision` 1 = APPROVE, 0 =
REJECT. Public-signal order: `[commitment, registeredVkHash, proofVkHash,
minimum, publicBalance, expiryBlock, currentBlock, recipient,
conditionRecipient, amount, maxTransfer, decision, taskId]`.

**Artifacts decision:** the wasm+zkey are *committed to this repo* (total
≈ 2.0 MB — small) so deploys have no download dependency at startup.
`npm run download-circuits` refreshes them from the official source and
re-exports the verification key.

## Run locally

```bash
npm install
AGENT_GAMES_HMAC_SECRET=<any-local-test-value> npm start   # listens on :3000
npm run prooftest   # circuit battery: 10 cases, correct decisions prove+verify, wrong decisions fail witness
npm run selftest    # endpoint test with a local test secret: decisions, signatures, 401s
```

## Environment

| Var | Notes |
|---|---|
| `AGENT_GAMES_HMAC_SECRET` | From the dashboard: reveal **once** via *Rotate Secret* on the agent settings page. Never commit it; `.env` is git-ignored. |
| `PORT` | Set automatically by Railway; defaults to 3000. |

## Deploy on Railway

1. Push this repo to a **public GitHub repository**.
2. Railway → New Project → Deploy from GitHub repo → select the repo.
   Root directory: repo root. Start command: `node server.js`
   (already set in `railway.json` / `package.json`).
3. Add env var `AGENT_GAMES_HMAC_SECRET` — but only *after* step 4 issues it;
   until then the service runs with `hmacConfigured=false` and rejects all
   POSTs (by design).
4. Generate a public domain (Railway → Settings → Networking), then register
   the agent on the Agent Games dashboard with the endpoint URL
   (`https://<your-domain>/gatekeeper`), reveal the HMAC secret via
   *Rotate Secret*, set it in Railway, and let the service redeploy.
5. Run the platform preflight from the dashboard; it must return the signed
   `{ ok: true, protocolVersion: "v1" }`.

> Free-tier sleep caveat (official rules §1.4): if the agent is asleep/offline
> when a task arrives, the task is forfeited. Use a hosting tier that stays up
> during round windows.

## Known unverified protocol details

These could **not** be confirmed from any public official source and must be
checked at first live preflight/practice task:

1. The exact byte format of the `x-agent-games-signature` header value —
   this code sends/expects bare lowercase hex HMAC-SHA256 (no `sha256=`
   prefix).
2. Whether the platform's health check uses `GET /health`, the preflight
   POST, or both (both are implemented).
3. Whether a real task's `task_id` enters the circuit exactly as implemented
   here (keccak256 of the string, mod p) — locally consistent and proof-
   verifying, but only a live scored/practice task can confirm the platform's
   independent public-inputs comparison.
4. zkVerify submission via Kurier/zkVerifyJS is **not** implemented: the
   official Gatekeeper response spec asks for the proof + public signals in
   the response itself; the `/build` Kurier flow is documented for proof
   submission generally. If the platform requires a Kurier `proof_tx`
   reference instead of the envelope's own `proof_tx`, that step (and a
   `KURIER_API_KEY`) must be added.
