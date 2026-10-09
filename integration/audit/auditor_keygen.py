#!/usr/bin/env python3
"""Auditor key generation (run once by the auditor).
Writes auditor_secret.ctx (keep private) and public.ctx (give to users).
CKKS: N = 8192, coeff_mod = [60, 40, 40, 60], scale = 2^40  (~128-bit security)."""
import tenseal as ts, argparse
ap = argparse.ArgumentParser(); ap.add_argument("--out", default="keys"); a = ap.parse_args()
import os; os.makedirs(a.out, exist_ok=True)
ctx = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
ctx.global_scale = 2 ** 40
ctx.generate_galois_keys()
open(f"{a.out}/auditor_secret.ctx", "wb").write(ctx.serialize(save_secret_key=True))
ctx.make_context_public()
open(f"{a.out}/public.ctx", "wb").write(ctx.serialize())
print(f"written {a.out}/auditor_secret.ctx (PRIVATE) and {a.out}/public.ctx")
