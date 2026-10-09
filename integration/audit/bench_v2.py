#!/usr/bin/env python3
"""Reproducible benchmark for the v2.1 pipeline (GuardedTransfer + audit), with
hardware/software metadata, warm-up runs discarded, 95% confidence intervals and
OS-level peak memory (ru_maxrss) for the prover (child processes) and for the
Python/TenSEAL side.

  cd integration/audit && python3 bench_v2.py            # defaults: 300 proofs, 1000 encryptions, 200 audits
Output: bench_v2_results.json and raw timings in bench_v2_raw.json
"""
import argparse, json, os, platform, resource, secrets, statistics, subprocess, sys, time
import tenseal as ts
from encoding import encode, decode
from keccak import keccak256
from poseidon import poseidon2

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
ap = argparse.ArgumentParser()
ap.add_argument("--proofs", type=int, default=300)
ap.add_argument("--enc", type=int, default=1000)
ap.add_argument("--audits", type=int, default=200)
ap.add_argument("--warmup", type=int, default=10)
a = ap.parse_args()
os.chdir(os.path.dirname(os.path.abspath(__file__)))
CIRC = "../circuits"
os.makedirs("bench_tmp", exist_ok=True)

def sh(cmd):
    try: return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60).stdout.strip()
    except Exception: return ""

def stats(x):
    m, s, n = statistics.mean(x), statistics.stdev(x), len(x)
    xs = sorted(x)
    return {"n": n, "mean": m, "std": s, "ci95": [m - 1.96 * s / n ** 0.5, m + 1.96 * s / n ** 0.5],
            "median": statistics.median(x), "p95": xs[int(0.95 * (n - 1))], "p99": xs[int(0.99 * (n - 1))],
            "min": xs[0], "max": xs[-1]}

def rss_mb(r):  # macOS reports bytes, Linux kilobytes
    return r / (1024 * 1024) if sys.platform == "darwin" else r / 1024

meta = {"platform": platform.platform(), "machine": platform.machine(),
        "cpu": sh("sysctl -n machdep.cpu.brand_string") or platform.processor(),
        "mem_bytes": sh("sysctl -n hw.memsize"), "python": sys.version.split()[0], "tenseal": ts.__version__,
        "node": sh("node --version"), "snarkjs": sh("npx snarkjs --version 2>&1 | head -1"),
        "power": sh("pmset -g batt | head -1"), "date": time.strftime("%Y-%m-%d %H:%M:%S")}

# keys (auditor) and public context (user)
sec = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
sec.global_scale = 2 ** 40
pub = ts.context_from(sec.serialize()); pub.make_context_public()

# 1) CKKS encryption of the 17-slot audit vector (user side)
enc_t, sizes = [], set()
for i in range(a.enc + a.warmup):
    v = encode(secrets.randbelow(1001), secrets.randbits(248))
    t0 = time.perf_counter(); ct = ts.ckks_vector(pub, v).serialize(); t1 = time.perf_counter()
    if i >= a.warmup: enc_t.append((t1 - t0) * 1e3); sizes.add(len(ct))

# 2) Auditor check: deserialize, decrypt, decode, Poseidon, keccak
aud_t, ok = [], 0
for i in range(a.audits + a.warmup):
    amt, s = secrets.randbelow(1001), secrets.randbits(248)
    ct = ts.ckks_vector(pub, encode(amt, s)).serialize(); h = keccak256(ct); cm = poseidon2(amt, s)
    t0 = time.perf_counter()
    assert keccak256(ct) == h
    am2, s2 = decode(ts.ckks_vector_from(sec, ct).decrypt())
    good = poseidon2(am2, s2 % P) == cm
    t1 = time.perf_counter()
    if i >= a.warmup: aud_t.append((t1 - t0) * 1e3); ok += good
py_rss = rss_mb(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)

# 3) Groth16 proof generation for GuardedTransfer via the snarkjs CLI (includes Node.js start-up)
inp = {"amount": "500", "secret": str(secrets.randbits(248)), "maxAmount": "1000",
       "cipherHash": str(int.from_bytes(keccak256(b"bench"), "big") % P),
       "actor": str(int("0x00b094FDA11687Eef53aCEF6a94F0ab0fE526c16", 16)), "chainId": "11155111"}
json.dump(inp, open("bench_tmp/input.json", "w"))
cmd = (f"npx snarkjs groth16 fullprove bench_tmp/input.json {CIRC}/guarded_transfer_js/guarded_transfer.wasm "
       f"{CIRC}/guarded_transfer_final.zkey bench_tmp/proof.json bench_tmp/public.json")
prv_t, errors = [], 0
for i in range(a.proofs + a.warmup):
    t0 = time.perf_counter(); r = subprocess.run(cmd, shell=True, capture_output=True); t1 = time.perf_counter()
    if r.returncode != 0: errors += 1; continue
    if i >= a.warmup: prv_t.append(t1 - t0)
    if i % 50 == 0: print(f"  proof {i}/{a.proofs + a.warmup}", flush=True)
vk = subprocess.run(f"npx snarkjs groth16 verify {CIRC}/verification_key.json bench_tmp/public.json bench_tmp/proof.json",
                    shell=True, capture_output=True, text=True).stdout
child_rss = rss_mb(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)

res = {"meta": meta, "warmup_discarded": a.warmup,
       "ckks_encrypt_17_slots_ms": stats(enc_t), "ciphertext_bytes": sorted(sizes),
       "audit_check_ms": stats(aud_t), "audit_consistent": f"{ok}/{a.audits}",
       "groth16_fullprove_cli_s": stats(prv_t) if len(prv_t) > 1 else None, "prove_errors": errors,
       "last_proof_verifies": "OK" in vk,
       "peak_rss_mb": {"python_tenseal_process": py_rss, "max_child_node_snarkjs": child_rss},
       "note": "proof time = wall clock of one `npx snarkjs groth16 fullprove` call (witness + proof), incl. Node.js start-up"}
json.dump(res, open("bench_v2_results.json", "w"), indent=1)
json.dump({"enc_ms": enc_t, "audit_ms": aud_t, "prove_s": prv_t}, open("bench_v2_raw.json", "w"))
print(json.dumps({k: v for k, v in res.items() if k != "meta"}, indent=1)); print(json.dumps(meta, indent=1))
