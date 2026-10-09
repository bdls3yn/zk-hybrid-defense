#!/usr/bin/env python3
"""User side: encrypt (amount, secret) under the auditor's PUBLIC CKKS context,
anchor keccak256(ciphertext), and write the circuit input for GuardedTransfer.

  --proof-amount lets you reproduce the reviewer's attack: the Groth16 proof is
  generated for one amount while the ciphertext encrypts another."""
import argparse, json, secrets, sys
import tenseal as ts
from encoding import encode
from keccak import keccak256
P_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617

ap = argparse.ArgumentParser()
ap.add_argument("--amount", type=int, required=True, help="amount encrypted in the CKKS ciphertext")
ap.add_argument("--proof-amount", type=int, help="amount used in the ZK proof (default = --amount)")
ap.add_argument("--max", type=int, default=1000)
ap.add_argument("--actor", required=True, help="sender address 0x...")
ap.add_argument("--chain", type=int, default=11155111)
ap.add_argument("--ctx", default="keys/public.ctx")
ap.add_argument("--out", default="tx")
a = ap.parse_args()
import os; os.makedirs(a.out, exist_ok=True)

secret = secrets.randbits(248)
ctx = ts.context_from(open(a.ctx, "rb").read())
ct = ts.ckks_vector(ctx, encode(a.amount, secret)).serialize()
h = keccak256(ct)
open(f"{a.out}/ciphertext.bin", "wb").write(ct)
inp = {"amount": str(a.proof_amount if a.proof_amount is not None else a.amount), "secret": str(secret),
       "maxAmount": str(a.max), "cipherHash": str(int.from_bytes(h, "big") % P_FIELD),
       "actor": str(int(a.actor, 16)), "chainId": str(a.chain)}
json.dump(inp, open(f"{a.out}/input.json", "w"), indent=1)
json.dump({"cipherHash": "0x" + h.hex(), "ciphertext_bytes": len(ct)}, open(f"{a.out}/meta.json", "w"), indent=1)
print(json.dumps({"cipherHash": "0x" + h.hex(), "ciphertext_bytes": len(ct), "out": a.out}))
# NOTE: the secret is inside the ciphertext and in input.json (needed by the prover only).
