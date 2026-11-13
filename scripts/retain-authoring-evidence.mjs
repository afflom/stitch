#!/usr/bin/env node
/** Select the exact output reported by real LexLean; never generate certificates. */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {lstatSync,readFileSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {retainSourceEvidence} from './retain-source-evidence.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
function readOutput(base,path){
  const parts=path.split('/');
  assert.ok(lstatSync(base).isDirectory(),'output base is not a nonsymlink directory');
  for(let i=1;i<parts.length;i++)assert.ok(lstatSync(resolve(base,...parts.slice(0,i))).isDirectory(),`output parent is not a nonsymlink directory: ${path}`);
  const full=resolve(base,path);assert.ok(lstatSync(full).isFile(),`output is not a nonsymlink file: ${path}`);
  return readFileSync(full);
}
export function selectAuthoringEvidence(stdout,base=root){
  const reports=[...stdout.matchAll(/^verified ([1-9][0-9]*) modules?; attestation ([0-9a-f]{64})\r?$/gm)];
  assert.equal(reports.length,1,'exactly one successful LexLean verification report is required');
  const count=Number(reports[0][1]),id=reports[0][2];
  const attestationPath=`app/.lexlean/verified/${id}/attestation.json`;
  const attestation=JSON.parse(readOutput(base,attestationPath));
  assert.equal(attestation.spec,'lexlean/attestation/2');assert.equal(attestation.status,'verified');
  assert.equal(attestation.attestation_id,id,'reported attestation identity differs');
  assert.match(attestation.build_id,/^[0-9a-f]{64}$/,'invalid exact build identity');
  const manifestPath=`app/.lexlean/build/${attestation.build_id}/manifest.json`;
  const bytes=readOutput(base,manifestPath),manifest=JSON.parse(bytes);
  assert.equal(manifest.spec,'lexlean/build-manifest/1');
  assert.deepEqual(attestation.build_manifest,{byte_length:bytes.length,sha256:digest(bytes)},'reported build manifest bytes differ');
  for(const key of ['build_id','source_id','semantic_id'])assert.equal(manifest[key],attestation[key],`${key} differs`);
  assert.equal(manifest.modules.length,count,'reported module count differs');
  return {attestationPath:resolve(base,attestationPath),manifestPath:resolve(base,manifestPath),attestationId:id,moduleCount:count};
}
export function retainAuthoringEvidence(stdout,base=root){
  const selected=selectAuthoringEvidence(stdout,base);
  return retainSourceEvidence(selected.attestationPath,selected.manifestPath,base);
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const args=process.argv.slice(2);
  if(args.length!==1||args[0].startsWith('--'))throw Error('usage: node scripts/retain-authoring-evidence.mjs <successful-lexlean-stdout.log>');
  const summary=retainAuthoringEvidence(readFileSync(resolve(args[0]),'utf8'));
  console.log(`Retained exact source attestation ${summary.attestation_id}; native Prism acceptance remains separate.`);
}
