const fs=require('fs');
function compile(tpl){let code='let __o="";';let re=/<%(=?)([\s\S]*?)%>/g,last=0,m;
 while((m=re.exec(tpl))){code+='__o+='+JSON.stringify(tpl.slice(last,m.index))+';';code+=m[1]?'__o+=('+m[2]+');':m[2];last=re.lastIndex;}
 code+='__o+='+JSON.stringify(tpl.slice(last))+';return __o;';return code;}
const vk=JSON.parse(fs.readFileSync('../circuits/verification_key.json'));
const ctx={vk_alpha_1:vk.vk_alpha_1,vk_beta_2:vk.vk_beta_2,vk_gamma_2:vk.vk_gamma_2,vk_delta_2:vk.vk_delta_2,IC:vk.IC,nPublic:vk.nPublic};
const fn=new Function(...Object.keys(ctx),compile(fs.readFileSync(process.env.SNARKJS_TEMPLATE || 'node_modules/snarkjs/templates/verifier_groth16.sol.ejs','utf8')));
let sol=fn(...Object.values(ctx)).replace('contract Groth16Verifier','contract GuardedTransferVerifier');
fs.writeFileSync('../src/GuardedTransferVerifier.sol',sol);console.log('nPublic',vk.nPublic);
