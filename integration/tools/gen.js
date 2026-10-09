const s=require('./sj.js'); const fs=require('fs'); const crypto=require('crypto');
const R=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const H=JSON.parse(fs.readFileSync('../results/hashes.json'));
const wasm=new Uint8Array(fs.readFileSync('../circuits/guarded_transfer_js/guarded_transfer.wasm'));
const zkey=new Uint8Array(fs.readFileSync('../circuits/guarded_transfer_final.zkey'));
const vk=JSON.parse(fs.readFileSync('../circuits/verification_key.json'));
const rnd=()=>BigInt('0x'+crypto.randomBytes(31).toString('hex'));
function flat(proof,pub){return [proof.pi_a[0],proof.pi_a[1],proof.pi_b[0][1],proof.pi_b[0][0],proof.pi_b[1][1],proof.pi_b[1][0],proof.pi_c[0],proof.pi_c[1],...pub].map(x=>BigInt(x).toString());}
async function prove(o){
  const inp={amount:o.amount.toString(),secret:(o.secret??rnd()).toString(),maxAmount:o.max.toString(),
    cipherHash:(BigInt(o.ct)%R).toString(),actor:BigInt(o.actor).toString(),chainId:o.chain.toString()};
  const t0=process.hrtime.bigint();
  const {proof,publicSignals}=await s.groth16.fullProve(inp,{type:'mem',data:wasm},{type:'mem',data:zkey});
  const dt=Number(process.hrtime.bigint()-t0)/1e9;
  return {flat:flat(proof,publicSignals),dt,ct:o.ct,label:o.label,proof,publicSignals};
}
(async()=>{
  const out={};
  const add=async(name,list)=>{out[name]=[];for(const o of list)out[name].push(await prove(o));};
  const L=31337;
  await add('benign',Array.from({length:40},(_,i)=>({amount:1+Math.floor(Math.random()*1000)%1000,max:1000,ct:i==0?H.real:H['ct'+i],actor:0x1000+i,chain:L})));
  await add('ddos',Array.from({length:12},(_,i)=>({amount:100,max:1000,ct:H['ct'+(50+i)],actor:0xBAD0,chain:L})));
  await add('sybil',Array.from({length:10},(_,i)=>({amount:100,max:1000,ct:H['ct'+(70+i)],actor:0x5B11,chain:L})));
  await add('esc',Array.from({length:6},(_,i)=>({amount:100,max:1000,ct:H['ct'+(90+i)],actor:0xE5C0,chain:L})));
  await add('sepolia',[{amount:500,max:1000,ct:H.real,actor:0x1000,chain:11155111}]);
  await add('policy',[{amount:1000000000,max:4294967295,ct:H['ct120'],actor:0xF00D,chain:L}]);
  // sanity: verify off-chain
  const ok=await s.groth16.verify(vk,out.benign[0].publicSignals,out.benign[0].proof);
  console.error('offchain verify',ok);
  // negative witness: amount>max must fail to prove
  try{await prove({amount:1001,max:1000,ct:H.ct1,actor:0x1000,chain:L});console.error('ERROR: out-of-range proof generated');}
  catch(e){console.error('out-of-range witness rejected: OK');}
  // old circuit proofs (ZK-HHCF v1)
  const ow=new Uint8Array(fs.readFileSync('../../circuits/range_proof/range_proof_js/range_proof.wasm')), oz=new Uint8Array(fs.readFileSync('../../circuits/range_proof/range_proof_final.zkey'));
  const op=async(a,m)=>{const {proof,publicSignals}=await s.groth16.fullProve({amount:String(a),maxAmount:String(m)},{type:'mem',data:ow},{type:'mem',data:oz});return flat(proof,publicSignals);};
  out.old={legit:await op(500,1000),inflated:await op(1000000000,4294967295)};
  fs.writeFileSync('../results/fixtures.json',JSON.stringify(out,(k,v)=>k==='proof'||k==='publicSignals'?undefined:v));
  process.exit(0);
})();
