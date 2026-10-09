"""Poseidon hash (BN254, circomlib-compatible) — pure Python reference used by the auditor.
Constants for t = 3 (2 inputs) are taken from circomlib/circuits/poseidon_constants.circom."""
import json, os, re
P_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
_HERE = os.path.dirname(os.path.abspath(__file__))
_CONST = os.path.join(_HERE, "poseidon_t3.json")

def _extract(src):
    txt = open(src).read()
    out = {}
    for name in ("C", "S", "M", "P"):
        start = txt.index(f"function POSEIDON_{name}(t)")
        blk = txt[start:]
        i = blk.index("t==3")
        j = blk.index("} else if", i)
        nums = [int(x, 0) for x in re.findall(r"0x[0-9a-fA-F]+|\b\d+\b", blk[i + 4:j])]
        out[name] = nums
    out["M"] = [out["M"][k*3:(k+1)*3] for k in range(3)]
    out["P"] = [out["P"][k*3:(k+1)*3] for k in range(3)]
    return out

def _load():
    return json.load(open(_CONST))

def _sigma(x): x2 = x*x % P_FIELD; return x2*x2 % P_FIELD * x % P_FIELD

def poseidon2(a, b):
    k = _load(); C, S, M, Pm = k["C"], k["S"], k["M"], k["P"]
    t, RF, RP = 3, 8, 57
    st = [0, a % P_FIELD, b % P_FIELD]
    st = [(st[j] + C[j]) % P_FIELD for j in range(t)]
    mix = lambda s, Mx: [sum(Mx[j][i]*s[j] for j in range(t)) % P_FIELD for i in range(t)]
    for r in range(RF//2 - 1):
        st = [_sigma(x) for x in st]
        st = [(st[j] + C[(r+1)*t + j]) % P_FIELD for j in range(t)]
        st = mix(st, M)
    st = [_sigma(x) for x in st]
    st = [(st[j] + C[(RF//2)*t + j]) % P_FIELD for j in range(t)]
    st = mix(st, Pm)
    for r in range(RP):
        st[0] = (_sigma(st[0]) + C[(RF//2+1)*t + r]) % P_FIELD
        base = (t*2-1)*r
        s0 = sum(S[base+i]*st[i] for i in range(t)) % P_FIELD
        st = [s0] + [(st[i] + st[0]*S[base+t+i-1]) % P_FIELD for i in range(1, t)]
    for r in range(RF//2 - 1):
        st = [_sigma(x) for x in st]
        st = [(st[j] + C[(RF//2+1)*t + RP + r*t + j]) % P_FIELD for j in range(t)]
        st = mix(st, M)
    st = [_sigma(x) for x in st]
    return sum(M[j][0]*st[j] for j in range(t)) % P_FIELD

if __name__ == "__main__":
    import sys
    json.dump(_extract(sys.argv[1]), open(_CONST, "w"))
    print("constants written")
