# My Gatekeeper Cannot Lie — the Circuit Won't Let It

*Written for the zkVerify Agent Games Creator Track (#AgentGames, @ZKVProtocol). Every number below comes from a test run I can show: the proof battery output and the endpoint self-test output are in the public repository, next to the code that produced them.*

Agent Games: https://agentgames.zkverify.io
Repository: <REPO_URL — fill after push>
Live endpoint: <ENDPOINT_URL — fill after deploy>

## The problem with trusting an agent

An AI agent that guards a payment has one job: say APPROVE or REJECT, correctly, in 60 seconds. The dangerous failure is not a crash — it is a confident wrong answer. "Trust me, I checked" is worth nothing when the checker is the one being checked.

Proof Gatekeeper, one of the four Agent Games tracks run by zkVerify (built by Horizen Labs), removes the trust. The agent must back every decision with a Groth16 zero-knowledge proof, generated with the tournament's own circuit, which the platform re-verifies against its own registered verification key (vkHash `0x6b79c6…d77b0`, from the official `/api/circuit-info`). The agent cannot swap in a friendlier key, and — this is the part I did not appreciate until I ran it — it cannot prove a wrong decision at all.

## What I built

A single Node.js server, standard library only (plus `snarkjs` 0.7.6 for proving):

- `POST /gatekeeper` receives a signed task envelope. The HMAC-SHA256 signature in `x-agent-games-signature` is verified over the **raw body, before parsing anything**. Bad or missing signature → 401, no decision, no proof. Fail closed, always.
- Seven documented checks decide the outcome: verification-key match, balance vs. minimum threshold, proof reuse (a persistent seen-set of `proof_tx` values), condition expiry by block height, recipient match, amount vs. single-transfer cap.
- For every provable decision the server generates a Groth16 proof with the official circuit artifacts (`gatekeeper.wasm`, 1,755,820 bytes, sha256 `be00aefe…`; `gatekeeper_final.zkey`, 309,750 bytes, sha256 `adfe95a4…`) and returns `{ decision, reason_code, proof, public_signals }`, signed with the same HMAC.
- PROOF_REUSED is answered without a proof — the scoring rules exclude it, and the circuit cannot prove a rejection of an otherwise-valid condition anyway (see below).

## The result that changed how I think about this

I ran a 10-case battery against the official circuit — every trap type, each with its correct and its incorrect decision:

- Valid condition → APPROVE: proof generates and **verifies OK**
- Valid condition → REJECT (the wrong call): **witness generation fails** — `Assert Failed. Error in template GatekeeperEvaluation_79 line: 102`
- VK substitution, threshold mismatch, expired condition, recipient mismatch, amount overflow → REJECT: proof generates and **verifies OK**; the APPROVE version of each fails at the same line 102

10 out of 10 cases behaved exactly as the rulebook intends. A wrong decision does not produce a bad proof that a verifier later catches. It produces *no proof at all* — the circuit asserts, inside itself, that the decision equals the result of its checks. The referee is not watching the game; the referee is built into the ball.

The endpoint self-test tells the same story end-to-end: 15 of 15 checks pass — health, signed preflight, a valid task answered APPROVE with a proof that re-verifies against the official verification key, all five provable traps answered REJECT with verifying proofs, reuse rejected without a proof, and unsigned requests refused.

## What is still honestly open

A Creator Track entry should not hide its gaps:

- Until the agent is registered, there is no platform-issued HMAC secret, so the deployed server deliberately rejects every POST. That is the fail-closed design working, not a bug.
- Three protocol details cannot be confirmed from public sources alone — the exact byte format of the signature header, whether the platform health-checks `GET /health` or only the signed preflight, and they are settled by the first live preflight, not by guessing harder.
- Generating a proof locally is not the same as a scored round. The scoreboard is the only receipt that counts, and this agent's first scored rounds are still ahead of it.

## Why verifiable agents actually matter

Replace "payment guard" with a trading bot, a loan approver, a content moderator, a contract signer. In every case the question is identical: the agent acted on its own — how do you know it followed the rules it claims to follow? zkVerify's answer is the one this tournament forced me to build: don't audit the agent's story afterwards. Make the agent produce, at decision time, a proof that the decision follows from the checks — a proof anyone can verify and the agent itself cannot forge.

The gate stays shut until the evidence says otherwise. And now the gate can prove it.

---

*Agent Games Season 01 runs 21 October – 21 November 2026, with 400,000 VFY in prizes across four tracks. Built for the Proof Gatekeeper track; submitted to the Creator Track. #AgentGames @ZKVProtocol*
