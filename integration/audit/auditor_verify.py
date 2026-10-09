#!/usr/bin/env python3
"""Auditor side: same-plaintext consistency check for one on-chain record.
  1. keccak256(ciphertext) == cipherHash stored on-chain
  2. decrypt with the auditor's secret CKKS key, round slots to integers
  3. Poseidon(amount', secret') == commitment stored on-chain
Prints a JSON verdict and the call to record it on-chain (ZKThreatGateway.recordAudit)."""
import argparse, json, time
import tenseal as ts
from encoding import decode
from keccak import keccak256
from poseidon import poseidon2

ap = argparse.ArgumentParser()
ap.add_argument("--ct", required=True); ap.add_argument("--commitment", required=True)
ap.add_argument("--cipherhash", required=True); ap.add_argument("--maxamount", type=int, default=1000)
ap.add_argument("--ctx", default="keys/auditor_secret.ctx"); ap.add_argument("--gateway", default="$GATEWAY")
a = ap.parse_args()

t0 = time.perf_counter()
ct = open(a.ct, "rb").read()
res = {"hash_ok": "0x" + keccak256(ct).hex() == a.cipherhash.lower()}
ctx = ts.context_from(open(a.ctx, "rb").read())
vec = ts.ckks_vector_from(ctx, ct).decrypt()
try:
    amount, secret = decode(vec)
    res.update(decoded=True, amount=amount, max_slot_error=max(abs(x - round(x)) for x in vec[:17]))
    cm = poseidon2(amount, secret)
    res["commitment_ok"] = cm == int(a.commitment, 0)
    res["policy_ok"] = amount <= a.maxamount
except ValueError as e:
    res.update(decoded=False, error=str(e), commitment_ok=False, policy_ok=False)
res["consistent"] = bool(res["hash_ok"] and res["commitment_ok"] and res["policy_ok"])
res["audit_ms"] = round((time.perf_counter() - t0) * 1000, 2)
print(json.dumps(res, indent=1))
print(f'\ncast send {a.gateway} "recordAudit(uint256,bool)" {int(a.commitment, 0)} {str(res["consistent"]).lower()} '
      '--rpc-url $ALCHEMY_SEPOLIA_URL --private-key $AUDITOR_KEY')
