#!/usr/bin/env bash
# Local demo (no blockchain): honest vs. reviewer's attack + homomorphic aggregate evaluation.
# Requirements on the Mac: python3 with tenseal, node/npx snarkjs.
set -euo pipefail
cd "$(dirname "$0")"
ACTOR=${ACTOR:-0x00b094FDA11687Eef53aCEF6a94F0ab0fE526c16}
CIRC=../circuits
python3 auditor_keygen.py
python3 client_prepare.py --amount 500 --actor "$ACTOR" --out honest
python3 client_prepare.py --amount 900 --proof-amount 1 --actor "$ACTOR" --out attack   # proof says 1, ciphertext says 900
for d in honest attack; do
  npx snarkjs wtns calculate $CIRC/guarded_transfer_js/guarded_transfer.wasm $d/input.json $d/w.wtns
  npx snarkjs groth16 prove $CIRC/guarded_transfer_final.zkey $d/w.wtns $d/proof.json $d/public.json
  npx snarkjs groth16 verify $CIRC/verification_key.json $d/public.json $d/proof.json
  CM=$(python3 -c "import json;print(json.load(open('$d/public.json'))[0])")
  H=$(python3 -c "import json;print(json.load(open('$d/meta.json'))['cipherHash'])")
  echo "== $d"; python3 auditor_verify.py --ct $d/ciphertext.bin --commitment "$CM" --cipherhash "$H" | tee $d/audit.txt
done
python3 he_aggregate_eval.py --trials 1000 --out he_aggregate_results.json
echo "DONE — results: honest/audit.txt, attack/audit.txt, he_aggregate_results.json"
