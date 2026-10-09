// Load snarkjs browser bundle in Node (npm registry is blocked in this sandbox)
const fs=require('fs');
const code=fs.readFileSync(process.env.SNARKJS_BUNDLE || require('path').join(__dirname,'node_modules/snarkjs/build/snarkjs.min.js'),'utf8');
module.exports=new Function(code+';return snarkjs;')();
