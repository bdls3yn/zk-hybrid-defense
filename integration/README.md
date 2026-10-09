# ZK-HHCF × ThreatDetector — integrated gateway (Dissertation §3.3)

This folder adds the **integration layer** that was missing between
`HybridGuardian` (§3.1) and `ThreatDetector` (§3.2). The v1 contracts in `../src`
are left untouched; everything new lives here.

## What is new

| Component | File | Role |
|---|---|---|
| Circuit | `circuits/guarded_transfer.circom` | Groth16 circuit: range policy, Poseidon commitment, ZK nullifier, binding to the ciphertext hash, sender and chain |
| Verifier | `src/GuardedTransferVerifier.sol` | snarkjs-generated verifier with 6 public signals |
| Gateway | `src/ZKThreatGateway.sol` | Single entry point: threat gate → policy/context binding → nullifier replay check → Groth16 verify → accept |
| Tests | `test/ZKThreatGateway.t.sol` | 20 unit + fuzz tests with **real proofs** |
| Evaluation | `test/Evaluation.t.sol` | 105-scenario on-EVM evaluation + 2 evasion experiments |
| Baseline | `test/BaselineV1Weaknesses.t.sol` | Shows weaknesses W1–W5 of the v1 contracts using real proofs |

Public signals (circom order): `[commitment, nullifier, maxAmount, cipherHash mod p, actor, chainId]`.

### Integration properties
- **I1:** The ZK nullifier `Poseidon(secret, chainId)` is the replay key.
- **I2:** The proof is bound to `keccak256(CKKS ciphertext)`, `msg.sender` and `block.chainid`.
- **I3:** `maxAmount` is fixed by the contract (`policyMax`).
- **I4:** Blocked or quarantined actors are rejected before pairing (6,336 gas instead of about 377k).
- **I5:** Cumulative score with a cap of 100, linear decay (1 point / 120 s), ALERT ≥ 70 → 30 s throttle, CRITICAL ≥ 90 → 24 h quarantine.
- **I6:** Only `msg.sender` is ever scored, so a third party cannot get someone else blocked (no griefing).

## Run

```bash
cd integration
forge test -vv                       # 28 tests
forge test --match-test test_Evaluation -vv   # prints the TP/FN/FP/TN table
```

## Deploy to Sepolia (uses ../.env — never hard-code keys)

```bash
cd integration
set -a; source ../.env; set +a
forge script script/DeployGateway.s.sol --rpc-url $ALCHEMY_SEPOLIA_URL \
      --private-key $PRIVATE_KEY --broadcast
```

The Sepolia fixture proof (`Fixtures.sepolia()`) is bound to actor `0x…1000`.
To submit a real transaction from your own wallet, generate a proof with
`actor = your address` and `chainId = 11155111`:

```bash
cd tools
snarkjs wtns calculate ../circuits/guarded_transfer_js/guarded_transfer.wasm input.json w.wtns
snarkjs groth16 prove ../circuits/guarded_transfer_final.zkey w.wtns proof.json public.json
snarkjs zkey export soliditycalldata public.json proof.json
```

`input.json` example: `{"amount":"500","secret":"<random < 2^248>","maxAmount":"1000","cipherHash":"<keccak256(ciphertext) mod p>","actor":"<your address as decimal>","chainId":"11155111"}`

## Reproducing the artefacts
- `tools/setup.js`: phase-2 setup on top of `../circuits/range_proof/pot12_final.ptau`.
- `tools/gen.js` and `tools/gen_eval.js`: proof fixtures.
- `tools/keccak.py`: dependency-free Keccak-256.

The tools load the snarkjs 0.7.4 bundle (`SNARKJS_BUNDLE=…/snarkjs.min.js`).
Results are in `results/results_summary.json`.

## Limitations (stated in the dissertation)
- The phase-2 setup is local, with one contributor plus a beacon. It is not a public ceremony.
- The equality between the CKKS plaintext and `amount` is **not** proven in ZK. The proof binds the ciphertext *hash*, and an authorised auditor checks consistency by decryption.
- The rules are per-address. Slow-rate DDoS (≤ 10 req/min) and distributed Sybil attacks (one tx per address) are not detected. This is measured in `test_EvasionLimits`.
- TenSEAL was not available in the build sandbox. Proof #0 is bound to the real `python/ciphertext.bin`; the other fixtures use 32-byte stand-in digests (only the binding matters for the contract).

## Same-plaintext audit (response to the KazNU review)

The Groth16 proof binds the *hash* of the CKKS ciphertext. It cannot prove that the ciphertext encrypts the same `amount`, because CKKS decryption is far too expensive to express inside a SNARK. v2.1 makes such a mismatch **detectable and punishable** instead:

1. The auditor generates the CKKS keys (`audit/auditor_keygen.py`). Users only receive `public.ctx`.
2. The user encrypts **both** `amount` and `secret`. The secret is split into 16 × 16-bit slots so that rounding recovers it exactly. The user then anchors `h = keccak256(ct)` (`audit/client_prepare.py`).
3. The proof outputs `commitment = Poseidon(amount, secret)`, which is stored on-chain.
4. The auditor decrypts the ciphertext, recomputes `Poseidon(amount', secret')` with the circomlib-compatible pure-Python `audit/poseidon.py`, and calls `recordAudit(commitment, consistent)`.
5. If the audit is inconsistent, the record is marked and the sender's score is set to 100, which puts the sender in quarantine for 24 h.

Run on the Mac (needs `tenseal` and `npx snarkjs`):

```bash
cd integration/audit
./run_audit_demo.sh         # honest vs. attack (proof amount 1, ciphertext 900) + homomorphic aggregate test
./sepolia_audit_demo.sh     # optional: same flow on Sepolia with recordAudit on-chain
```

Tests: `test/Audit.t.sol` (7 tests). Measured locally on anvil: `recordAudit` costs 31,769 gas for a consistent verdict and 43,365 gas for an inconsistent one.

Limitation (stated explicitly): detection happens after the transaction (ex-post) and relies on the auditor holding the key honestly. The attack transaction itself is accepted on-chain. Preventing it in advance would require a verifiable-encryption proof, which is left to future work.
