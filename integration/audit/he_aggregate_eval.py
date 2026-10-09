#!/usr/bin/env python3
"""Homomorphic computation over encrypted amounts (why CKKS and not a plain commitment):
the auditor obtains the encrypted DAILY TOTAL of K transfers of one address and a
fee-adjusted total, decrypting only the aggregates, never the individual amounts.
Reports precision (absolute error), timing and OS-level peak memory (ru_maxrss)."""
import argparse, json, random, resource, statistics, sys, time
import tenseal as ts
from encoding import encode
ap = argparse.ArgumentParser()
ap.add_argument("--trials", type=int, default=1000); ap.add_argument("--k", type=int, default=10)
ap.add_argument("--fee", type=float, default=0.997); ap.add_argument("--daily-limit", type=int, default=5000)
ap.add_argument("--out", default="he_aggregate_results.json")
a = ap.parse_args()
sec = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
sec.global_scale = 2 ** 40; sec.generate_galois_keys()
pub = ts.context_from(sec.serialize()); pub.make_context_public()

err_sum, err_fee, t_add, t_mul, t_dec, wrong_decisions = [], [], [], [], [], 0
random.seed(42)
for _ in range(a.trials):
    amounts = [random.randint(1, 1000) for _ in range(a.k)]
    cts = [ts.ckks_vector(pub, encode(x, random.getrandbits(248))) for x in amounts]
    t0 = time.perf_counter(); total = cts[0]
    for c in cts[1:]: total = total + c          # homomorphic addition (depth 0)
    t1 = time.perf_counter(); fee_total = total * a.fee           # multiplication by a plaintext scalar (consumes one level)
    t2 = time.perf_counter()
    s = ts.ckks_vector_from(sec, total.serialize()).decrypt()[0]
    f = ts.ckks_vector_from(sec, fee_total.serialize()).decrypt()[0]
    t3 = time.perf_counter()
    true_sum = sum(amounts)
    err_sum.append(abs(s - true_sum)); err_fee.append(abs(f - true_sum * a.fee))
    wrong_decisions += (round(s) > a.daily_limit) != (true_sum > a.daily_limit)
    t_add.append((t1 - t0) * 1e3); t_mul.append((t2 - t1) * 1e3); t_dec.append((t3 - t2) * 1e3)

def st(x): return {"mean": statistics.mean(x), "std": statistics.stdev(x), "max": max(x)}
rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
res = {"trials": a.trials, "k": a.k, "params": "CKKS N=8192, q=[60,40,40,60], scale=2^40",
       "abs_error_sum": st(err_sum), "abs_error_fee_mul": st(err_fee),
       "limit_decisions_wrong": wrong_decisions,
       "ms_add_k_ciphertexts": st(t_add), "ms_plain_mul": st(t_mul), "ms_decrypt_two": st(t_dec),
       "peak_rss_mb": rss / (1024 * 1024) if sys.platform == "darwin" else rss / 1024,
       "python": sys.version.split()[0], "tenseal": ts.__version__}
json.dump(res, open(a.out, "w"), indent=1); print(json.dumps(res, indent=1))
