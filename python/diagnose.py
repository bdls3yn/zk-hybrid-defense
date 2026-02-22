import json
from web3 import Web3
from pathlib import Path

BASE        = Path(__file__).parent.parent
PROOF_PATH  = BASE / "circuits/range_proof/proof.json"
PUBLIC_PATH = BASE / "circuits/range_proof/public.json"

RPC_URL  = "https://eth-sepolia.g.alchemy.com/v2/0vnRc7KUEXrwkQlHasBEI"
VERIFIER = Web3.to_checksum_address("0x8e64412E481541e0B3f934d0B63ee6370d5f577F")
GUARDIAN = Web3.to_checksum_address("0x004F12B866b7730a2332d6433F1f83a53b698027")
OWNER    = Web3.to_checksum_address("0x00b094fda11687eef53acef6a94f0ab0fe526c16")

VERIFIER_ABI = [{
    "inputs": [
        {"name": "_pA",         "type": "uint256[2]"},
        {"name": "_pB",         "type": "uint256[2][2]"},
        {"name": "_pC",         "type": "uint256[2]"},
        {"name": "_pubSignals", "type": "uint256[2]"}
    ],
    "name": "verifyProof",
    "outputs": [{"name": "", "type": "bool"}],
    "stateMutability": "view",
    "type": "function"
}]

w3 = Web3(Web3.HTTPProvider(RPC_URL))

proof  = json.loads(PROOF_PATH.read_text())
public = json.loads(PUBLIC_PATH.read_text())

pA = [int(proof["pi_a"][0]), int(proof["pi_a"][1])]
pB = [
    [int(proof["pi_b"][0][1]), int(proof["pi_b"][0][0])],
    [int(proof["pi_b"][1][1]), int(proof["pi_b"][1][0])]
]
pC         = [int(proof["pi_c"][0]), int(proof["pi_c"][1])]
pubSignals = [int(x) for x in public]

verifier = w3.eth.contract(address=VERIFIER, abi=VERIFIER_ABI)

print("=" * 55)
print("  Verifier Diaqnostikası (Yeni)")
print("=" * 55)

# 1. Bytecode ölçüsü
code = w3.eth.get_code(VERIFIER)
print(f"\n[1] Verifier bytecode : {len(code)} bayt")

# 2. Birbaşa call (gas xərcsiz)
try:
    result = verifier.functions.verifyProof(pA, pB, pC, pubSignals).call()
    print(f"[2] verifyProof nəticə: {result}")
except Exception as e:
    print(f"[2] verifyProof XƏTA  : {e}")

# 3. Gas estimasiyası (yalnız verifier üçün)
try:
    gas = verifier.functions.verifyProof(
        pA, pB, pC, pubSignals
    ).estimate_gas({"from": OWNER})
    print(f"[3] Verifier gas      : {gas:,}")
    if gas < 500_000:
        print("    ✅ Normal — precompile işləyir")
    elif gas < 5_000_000:
        print("    ⚠️  Yüksək — precompile problem var")
    else:
        print("    ❌ Kritik — pure Solidity hesablama")
except Exception as e:
    print(f"[3] Gas estimasiya    : {e}")

# 4. RangeProofVerifier.sol-un ilk 5 sətri
sol_path = BASE / "src/RangeProofVerifier.sol"
lines = sol_path.read_text().split("\n")
print(f"\n[4] RangeProofVerifier.sol:")
for i, line in enumerate(lines[:8]):
    print(f"    {i+1:02d}: {line}")

print("=" * 55)
