const s=require('./sj.js'); const fs=require('fs'); const crypto=require('crypto');
const mem=()=>({type:'mem'});
(async()=>{
  const logger=console;
  const pf={type:'mem',data:new Uint8Array(fs.readFileSync('../../circuits/range_proof/pot12_final.ptau'))};
  const r1cs=new Uint8Array(fs.readFileSync('../circuits/guarded_transfer.r1cs'));
  let z0=mem(); await s.zKey.newZKey({type:'mem',data:r1cs}, {type:'mem',data:pf.data}, z0);
  let z1=mem(); await s.zKey.contribute(z0,z1,'z1',crypto.randomBytes(32).toString('hex'));
  let zf=mem(); await s.zKey.beacon(z1,zf,'zbeacon','0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',10);
  fs.writeFileSync('../circuits/guarded_transfer_final.zkey', Buffer.from(zf.data));
  const vk=await s.zKey.exportVerificationKey({type:'mem',data:zf.data});
  fs.writeFileSync('../circuits/verification_key.json', JSON.stringify(vk,null,1));
  const ok=await s.zKey.verifyFromR1cs({type:'mem',data:r1cs},{type:'mem',data:pf.data},{type:'mem',data:zf.data});
  console.log('zkey verify:',ok);
  const tpl=fs.readFileSync(process.env.SNARKJS_TEMPLATE || 'node_modules/snarkjs/templates/verifier_groth16.sol.ejs','utf8');
  const sol=await s.zKey.exportSolidityVerifier({type:'mem',data:zf.data},{groth16:tpl});
  fs.writeFileSync('../src/GuardedTransferVerifier.sol', sol);
  process.exit(0);
})();
async function getCurve(){ return 'bn128'; }
