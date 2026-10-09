#!/usr/bin/env bash
# On-chain demo on Sepolia: deploy ZKThreatGateway v2.1 (with auditor role), submit an honest
# and a malicious transfer, run the off-chain audit, record verdicts on-chain.
# Run from integration/audit after run_audit_demo.sh. Uses ../../.env (ALCHEMY_SEPOLIA_URL, PRIVATE_KEY).
set -euo pipefail
cd "$(dirname "$0")"
set -a; source ../../.env; set +a
RPC=$ALCHEMY_SEPOLIA_URL
VERIFIER=${VERIFIER:-0x6D5dD243D61EFbfa62e6c7a28eDe757c0A4B6f6D}   # GuardedTransferVerifier (unchanged circuit)
ME=$(cast wallet address --private-key "$PRIVATE_KEY")
GW=$(cd .. && forge create src/ZKThreatGateway.sol:ZKThreatGateway --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast \
       --constructor-args $VERIFIER 1000 | awk '/Deployed to:/{print $3}')
echo "ZKThreatGateway v2.1: $GW"
cast send $GW "setAuditor(address)" $ME --rpc-url $RPC --private-key $PRIVATE_KEY >/dev/null   # demo: deployer acts as auditor
for d in honest attack; do
  ARGS=$(npx snarkjs zkey export soliditycalldata $d/public.json $d/proof.json | python3 -c "
import json,sys; a=json.loads('['+sys.stdin.read()+']')
f=lambda x: '['+','.join(f(y) if isinstance(y,list) else y for y in x)+']'
print(' '.join(f(x) for x in a))")
  H=$(python3 -c "import json;print(json.load(open('$d/meta.json'))['cipherHash'])")
  CM=$(python3 -c "import json;print(json.load(open('$d/public.json'))[0])")
  echo "== $d: submit"
  cast send $GW "submit(uint256[2],uint256[2][2],uint256[2],uint256[6],bytes32)" $ARGS $H --rpc-url $RPC --private-key $PRIVATE_KEY | grep -E "transactionHash|gasUsed|status"
  OK=$(python3 auditor_verify.py --ct $d/ciphertext.bin --commitment "$CM" --cipherhash "$H" | python3 -c "import sys,json;t=sys.stdin.read();print(str(json.loads(t[:t.rindex('}')+1])['consistent']).lower())")
  echo "== $d: audit verdict consistent=$OK"
  cast send $GW "recordAudit(uint256,bool)" $CM $OK --rpc-url $RPC --private-key $PRIVATE_KEY | grep -E "transactionHash|gasUsed|status"
done
echo "score of $ME: $(cast call $GW 'currentScore(address)(uint8)' $ME --rpc-url $RPC)  level: $(cast call $GW 'riskLevel(address)(string)' $ME --rpc-url $RPC)"
