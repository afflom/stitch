import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {chmodSync,cpSync,mkdirSync,mkdtempSync,readFileSync,rmSync,symlinkSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {selectAuthoringEvidence} from '../scripts/retain-authoring-evidence.mjs';
const root=resolve(import.meta.dirname,'..');
const original=JSON.parse(readFileSync(join(root,'product/source-attestation.json')));
const originalManifest=JSON.parse(readFileSync(join(root,'product/source-build-manifest.json')));
const stdout=`verified ${originalManifest.modules.length} modules; attestation ${original.attestation_id}\n`;
function fixture(t){
  const base=mkdtempSync(join(tmpdir(),'stitch-source-authoring-'));t.after(()=>rmSync(base,{recursive:true,force:true}));
  const attestationPath=join(base,'app/.lexlean/verified',original.attestation_id,'attestation.json');
  const manifestPath=join(base,'app/.lexlean/build',original.build_id,'manifest.json');
  for(const [to,from] of [[attestationPath,'product/source-attestation.json'],[manifestPath,'product/source-build-manifest.json']]){mkdirSync(dirname(to),{recursive:true});cpSync(join(root,from),to);}
  return {base,attestationPath,manifestPath};
}
test('authoring selector uses the exact reported original ID, not directory order',t=>{
  const x=fixture(t);mkdirSync(join(x.base,'app/.lexlean/verified','0'.repeat(64)));mkdirSync(join(x.base,'app/.lexlean/verified','f'.repeat(64)));
  assert.deepEqual(selectAuthoringEvidence(stdout,x.base),{attestationPath:x.attestationPath,manifestPath:x.manifestPath,attestationId:original.attestation_id,moduleCount:originalManifest.modules.length});
});
test('missing, duplicate, malformed and misleading success text refuses',t=>{
  const x=fixture(t);
  for(const log of ['',stdout+stdout,`prefix ${stdout}`,stdout.replace(original.attestation_id,'../wrong'),`verified attestation: ${original.attestation_id}\n`])assert.throws(()=>selectAuthoringEvidence(log,x.base),/exactly one/);
  assert.throws(()=>selectAuthoringEvidence(stdout.replace(String(originalManifest.modules.length),'999'),x.base),/module count differs/);
});
test('exact selected attestation and build byte identity are mandatory',t=>{
  const x=fixture(t);
  const changed={...original,attestation_id:'0'.repeat(64)};writeFileSync(x.attestationPath,JSON.stringify(changed));
  assert.throws(()=>selectAuthoringEvidence(stdout,x.base),/attestation identity differs/);
  cpSync(join(root,'product/source-attestation.json'),x.attestationPath);
  writeFileSync(x.manifestPath,readFileSync(x.manifestPath,'utf8')+'\n');assert.throws(()=>selectAuthoringEvidence(stdout,x.base),/manifest bytes differ/);
});
test('selected output aliases cannot escape the exact build directories',t=>{
  const x=fixture(t),saved=join(x.base,'original.json');cpSync(x.manifestPath,saved);rmSync(x.manifestPath);symlinkSync(saved,x.manifestPath);
  assert.throws(()=>selectAuthoringEvidence(stdout,x.base),/nonsymlink file/);
});
function orchestration(t,failVerify=false){
  const base=mkdtempSync(join(tmpdir(),'stitch-authoring-boundary-'));t.after(()=>rmSync(base,{recursive:true,force:true}));
  for(const path of ['app','scripts','bin','node_modules/prism-code'])mkdirSync(join(base,path),{recursive:true});
  cpSync(join(root,'scripts/author-source.sh'),join(base,'scripts/author-source.sh'));
  cpSync(join(root,'scripts/check-model-sdk.sh'),join(base,'scripts/check-model-sdk.sh'));
  for(const path of ['prismpm.lock','standards.lock','package-lock.json'])cpSync(join(root,path),join(base,path));
  writeFileSync(join(base,'node_modules/prism-code/package.json'),'{}');
  // A real version check sees this isolated package metadata; no compiler is emulated.
  writeFileSync(join(base,'node_modules/prism-code/package.json'),JSON.stringify({version:'0.7.2'}));
  const log=join(base,'calls.jsonl');
  const preamble=`#!${process.execPath}\nconst fs=require('node:fs'),args=process.argv.slice(2);fs.appendFileSync(process.env.RECORD_CALLS,JSON.stringify({kind:require('node:path').basename(process.argv[1]),args})+'\\n');\n`;
  writeFileSync(join(base,'bin/node'),preamble+`if(args[0]==='-e'){const r=require('node:child_process').spawnSync(${JSON.stringify(process.execPath)},args,{stdio:'inherit'});process.exit(r.status??1);}if(!['scripts/check-facets.mjs','node_modules/prism-code/bin/prism-code.mjs','scripts/retain-authoring-evidence.mjs','scripts/check-model.mjs','scripts/check-product.mjs','scripts/check-source-evidence.mjs'].includes(args[0]))process.exit(90);\n`);
  writeFileSync(join(base,'bin/docker'),preamble+`if(args[0]!=='pull'&&args[0]!=='run')process.exit(91);if(args.at(-1)==='cd app && lexlean verify --all'){console.log(${JSON.stringify(stdout.trim())});process.exit(process.env.FAIL_VERIFY==='1'?7:0);}\n`);
  for(const name of ['node','docker'])chmodSync(join(base,'bin',name),0o755);
  const result=spawnSync('bash',['scripts/author-source.sh'],{cwd:base,env:{...process.env,PATH:join(base,'bin')+':'+process.env.PATH,PRISM_CODE_DRY_RUN:'',RECORD_CALLS:log,FAIL_VERIFY:failVerify?'1':'0'},encoding:'utf8',timeout:20000,maxBuffer:2**20});
  const calls=readFileSync(log,'utf8').trim().split('\n').map(JSON.parse);return {result,calls};
}
test('recording boundary keeps the official axiom writer on host between SDK prepare and proof',t=>{
  const {result,calls}=orchestration(t);assert.equal(result.status,0,result.stderr);assert.equal(result.error,undefined);
  const prepare=calls.findIndex(x=>x.kind==='docker'&&x.args.at(-1)==='--prepare');
  const writer=calls.findIndex(x=>x.kind==='node'&&x.args[0]==='node_modules/prism-code/bin/prism-code.mjs');
  const verify=calls.findIndex(x=>x.kind==='docker'&&x.args.at(-1)==='cd app && lexlean verify --all');
  const retain=calls.findIndex(x=>x.kind==='node'&&x.args[0]==='scripts/retain-authoring-evidence.mjs');
  assert.ok(prepare>=0&&prepare<writer&&writer<verify&&verify<retain);
  assert.deepEqual(calls[writer].args,['node_modules/prism-code/bin/prism-code.mjs','axioms','--write','--project','app']);
  const image=JSON.parse(readFileSync(join(root,'prismpm.lock'))).sdk_image;
  for(const call of calls.filter(x=>x.kind==='docker'&&x.args[0]==='run')){
    assert.ok(call.args.includes(image));assert.ok(call.args.includes('--read-only'));assert.ok(!call.args.some(x=>x.includes('docker.sock')));
    assert.ok(!call.args.some(x=>x.includes('prism-code')),'no nested Docker writer');
  }
  assert.match(result.stdout,/PP5007 has not been cleared/);
});
test('a failed real-process boundary cannot retain proof even if stdout resembles success',t=>{
  const {result,calls}=orchestration(t,true);assert.equal(result.status,7,result.stderr);
  assert.ok(!calls.some(x=>x.args[0]==='scripts/retain-authoring-evidence.mjs'));
  assert.ok(!calls.some(x=>x.args[0]==='scripts/check-product.mjs'));
});
test('hosted authoring is fork-scoped, read-only publication and separate from native acceptance',()=>{
  const workflow=readFileSync(join(root,'.github/workflows/source-authoring.yml'),'utf8');
  assert.match(workflow,/contents: read/);assert.doesNotMatch(workflow,/contents: write|git push|merge_pull_request|prismpm .*verify/);
  assert.match(workflow,/github.repository == 'afflom\/stitch'/);assert.match(workflow,/refs\/heads\/feat\/complete-stitch-prism/);
  assert.match(workflow,/persist-credentials: false/);assert.match(workflow,/if: always\(\)/);assert.match(workflow,/authoring\.patch/);
});
