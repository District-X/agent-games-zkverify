# X Thread — Creator Track (post from @ForgottenMalaka, fill <REPO_URL> first)

1/ I built a Proof Gatekeeper agent for @ZKVProtocol Agent Games — an agent that guards payments and has to PROVE every APPROVE/REJECT with a zero-knowledge proof.

Then the circuit taught me something: my agent cannot lie. Not "should not". Cannot. 🧵 #AgentGames

2/ The platform sends a signed task. My agent verifies the HMAC signature on the raw body before parsing anything — bad signature, 401, no work done. Fail closed, always.

Then 7 checks: VK match, threshold, proof reuse, expiry, recipient, amount cap.

3/ Every decision is backed by a Groth16 proof from the tournament's own circuit, re-verified by the platform against ITS registered key (vkHash 0x6b79c6…d77b0). The agent can't swap in a friendlier key.

4/ I ran a 10-case battery. Valid → APPROVE: proof verifies ✅. Every trap → REJECT: proof verifies ✅.

And every WRONG decision? Witness generation fails inside the circuit itself — Assert Failed, GatekeeperEvaluation_79 line 102. No proof exists for a lie.

5/ Endpoint self-test: 15/15 pass — signed preflight, valid task + 5 traps with re-verified proofs, reuse rejected, unsigned requests refused.

The code, the test outputs, and the receipts are public: <REPO_URL>

6/ This is why verifiable agents matter. A trading bot, a loan approver, a contract signer — "trust me, I checked" is not an audit.

zkVerify's answer: the agent proves it at decision time, or it didn't happen. #AgentGames @ZKVProtocol
