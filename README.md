# Proof Gatekeeper — zkVerify Agent Games Season 01

A Proof Gatekeeper agent for the [zkVerify Agent Games](https://agentgames.zkverify.io):
it receives signed payment tasks, decides **APPROVE** or **REJECT**, and proves
every decision with a Groth16 zero-knowledge proof (BN254, Circom 2.x) that
the platform re-verifies against its own registered verification key.

## How it works

1. The platform POSTs a signed task envelope to `POST /gatekeeper`.
2. The server verifies the HMAC signature (`x-agent-games-signature`) over
   the raw body **before** parsing anything. Bad signature → 401.
3. It decides deterministically — APPROVE only when every field checks out:
   proof VK matches the registered VK, public balance meets the minimum,
   condition not expired, recipient matches, amount within the cap, and the
   proof reference has not been seen under another task.
4. It generates a Groth16 proof of the decision with the official
   `gatekeeper` circuit (`snarkjs`) and returns decision + reason code +
   proof + public signals, signed with the same HMAC.
5. Any uncertainty fails closed: REJECT.

Scoring (per the official rules): correct decision +12, wrong APPROVE −6,
wrong REJECT −3, timeout −2, missing/invalid proof −2, plus a reliability
bonus of +0 to +5 pro-rated by verified proofs.

## Run it

```bash
npm install
cp .env.example .env   # set AGENT_GAMES_HMAC_SECRET from the dashboard
npm start              # listens on :8080 — POST /gatekeeper, GET /health
npm test               # decision-logic unit tests (12 cases, no proofs)
```

## Files

- `server.js` — HTTP server (Node stdlib only), HMAC in/out, preflight.
- `gatekeeper/decide.js` — the 7-trap decision logic.
- `gatekeeper/prove.js` — Groth16 proof generation (official circuit).
- `circuits/` — official artifacts: `gatekeeper.wasm`,
  `gatekeeper_final.zkey`, `verification_key.json`
  (registered vk hash `0x6b79c6…d77b0`).
- `test-decide.js`, `test-proof.js` — unit + local proof tests.

## Notes

- The circuit is the referee: a dishonest APPROVE is not just rejected, it
  is *unprovable* — witness generation fails, so no proof exists to send.
- The seen-set for proof reuse lives in memory; restart the server and it
  forgets previously seen proof references.
- No wallet keys live in this repo. The server never signs a transaction
  or spends anything.
