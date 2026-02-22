import json
import tenseal as ts
from web3 import Web3
from pathlib import Path

BASE            = Path(__file__).parent.parent
PROOF_ARGS_PATH = BASE / "python/proof_args.json"
CIPHER_PATH     = BASE / "python/ciphertext.bin"

RPC_URL     = "https://eth-sepolia.g.alchemy.com/v2/0vnRc7KUEXrwkQlHasBEI"
PRIVATE_KEY = "0x2ce2c264038825afe4518874ea0d6ecf24728a6659389f7fc4338e296cf397a1"
GUARDIAN    = "0x5FC0Dbf8f4D1fE65A313354908f7ceE3110aCe78"

ABI = [
    {
        "inputs": [
            {"name": "_pA",         "type": "uint256[2]"},
            {"name": "_pB",         "type": "uint256[2][2]"},
            {"name": "_pC",         "type": "uint256[2]"},
            {"name": "_pubSignals", "type": "uint256[2]"},
            {"name": "_ciphertext", "type": "bytes"}
        ],
        "name": "submitVerifiedTransaction",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getStats",
        "outputs": [
            {"name": "verified", "type": "uint256"},
            {"name": "rejected", "type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

def homomorphic_encrypt(amount: float) -> bytes:
    print(f"\n[1] Homomorfik şifrələmə: amount={amount}")
    ctx = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=8192,
        coeff_mod_bit_sizes=[60, 40, 40, 60]
    )
    ctx.global_scale = 2**40
    ctx.generate_galois_keys()

    encrypted   = ts.ckks_vector(ctx, [amount])
    full_cipher = encrypted.serialize()

    CIPHER_PATH.write_bytes(full_cipher)
    print(f"    ✅ Lokal saxlandı  : {len(full_cipher):,} bayt")

    cipher_hash = Web3.keccak(full_cipher)
    print(f"    ✅ On-chain hash   : {cipher_hash.hex()}")
    return cipher_hash

def load_proof():
    print("\n[2] ZK sübutu oxunur (snarkjs formatı)...")
    args = json.loads(PROOF_ARGS_PATH.read_text())

    pA         = [int(args["pA"][0], 16)  if str(args["pA"][0]).startswith("0x") else int(args["pA"][0]),
                  int(args["pA"][1], 16)  if str(args["pA"][1]).startswith("0x") else int(args["pA"][1])]

    pB         = [
        [int(args["pB"][0][0], 16) if str(args["pB"][0][0]).startswith("0x") else int(args["pB"][0][0]),
         int(args["pB"][0][1], 16) if str(args["pB"][0][1]).startswith("0x") else int(args["pB"][0][1])],
        [int(args["pB"][1][0], 16) if str(args["pB"][1][0]).startswith("0x") else int(args["pB"][1][0]),
         int(args["pB"][1][1], 16) if str(args["pB"][1][1]).startswith("0x") else int(args["pB"][1][1])]
    ]

    pC         = [int(args["pC"][0], 16)  if str(args["pC"][0]).startswith("0x") else int(args["pC"][0]),
                  int(args["pC"][1], 16)  if str(args["pC"][1]).startswith("0x") else int(args["pC"][1])]

    pubSignals = [int(x, 16) if str(x).startswith("0x") else int(x) for x in args["pubSignals"]]

    print(f"    ✅ Sübut yükləndi  | pubSignals: {pubSignals}")
    return pA, pB, pC, pubSignals

def submit_to_contract(pA, pB, pC, pubSignals, cipher_hash: bytes):
    print("\n[3] Sepolia-ya göndərilir...")
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    assert w3.is_connected(), "❌ RPC bağlantısı yoxdur!"

    account  = w3.eth.account.from_key(PRIVATE_KEY)
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(GUARDIAN), abi=ABI
    )

    fn = contract.functions.submitVerifiedTransaction(
        pA, pB, pC, pubSignals, cipher_hash
    )

    try:
        estimated = fn.estimate_gas({"from": account.address})
        gas_limit = int(estimated * 1.3)
        print(f"    ⛽ Gas estimasiyası: {estimated:,} → limit: {gas_limit:,}")
    except Exception as e:
        print(f"    ⚠️  Estimasiya uğursuz: {e}")
        gas_limit = 500_000
        print(f"    ⛽ Ehtiyat limit  : {gas_limit:,}")

    tx = fn.build_transaction({
        "from":                 account.address,
        "nonce":                w3.eth.get_transaction_count(account.address),
        "gas":                  gas_limit,
        "maxFeePerGas":         w3.to_wei("2", "gwei"),
        "maxPriorityFeePerGas": w3.to_wei("1", "gwei"),
    })

    signed  = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"    ✅ TX göndərildi   : {tx_hash.hex()}")
    print(f"    🔗 https://sepolia.etherscan.io/tx/{tx_hash.hex()}")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    status  = "✅ Uğurlu" if receipt.status == 1 else "❌ Uğursuz"
    print(f"    {status} | Blok: {receipt.blockNumber} | Gas: {receipt.gasUsed:,}")
    return receipt

def get_stats():
    w3       = Web3(Web3.HTTPProvider(RPC_URL))
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(GUARDIAN), abi=ABI
    )
    verified, rejected = contract.functions.getStats().call()
    print(f"\n[4] Kontrakt statistikası:")
    print(f"    ✅ Doğrulanmış : {verified}")
    print(f"    ❌ Rədd edilmiş: {rejected}")

if __name__ == "__main__":
    print("=" * 55)
    print("  ZK-Homomorfik Hibrid Çərçivə — 3.1 Test")
    print("=" * 55)

    AMOUNT = 500.0
    cipher_hash      = homomorphic_encrypt(AMOUNT)
    pA, pB, pC, sigs = load_proof()
    receipt          = submit_to_contract(pA, pB, pC, sigs, cipher_hash)
    get_stats()

    print("\n" + "=" * 55)
    print("  ✅ 3.1 Hibrid inteqrasiya tamamlandı!")
    print("=" * 55)
