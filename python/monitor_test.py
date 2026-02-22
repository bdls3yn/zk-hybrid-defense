import sys
print("Python:", sys.version)

try:
    from web3 import Web3
    print("✅ web3 import OK")
except Exception as e:
    print("❌ web3:", e)

try:
    from web3.middleware import ExtraDataToPOAMiddleware
    print("✅ middleware import OK")
except Exception as e:
    print("❌ middleware:", e)
    try:
        from web3.middleware import geth_poa_middleware
        print("✅ geth_poa_middleware OK (köhnə versiya)")
    except Exception as e2:
        print("❌ geth_poa_middleware:", e2)

try:
    w3 = Web3(Web3.HTTPProvider(
        "https://eth-sepolia.g.alchemy.com/v2/0vnRc7KUEXrwkQlHasBEI"
    ))
    print("✅ Bağlantı:", w3.is_connected())
    print("✅ Blok nömrəsi:", w3.eth.block_number)
except Exception as e:
    print("❌ RPC:", e)
