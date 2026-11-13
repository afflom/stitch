import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, cpSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { generateFacets, checkFacets, validateFacetReferences } from '../scripts/check-facets.mjs';
const root=resolve(import.meta.dirname,'..');
test('product facets are deterministic and exactly current, with complete action coverage',()=>{
  const a=generateFacets(root),b=generateFacets(root);assert.deepEqual([...a.outputs],[...b.outputs]);
  assert.deepEqual(checkFacets(root),a.catalog);
  assert.equal(a.catalog.modules.length,9);assert.ok(a.catalog.features.length>=31);
  for(const f of a.catalog.features){assert.ok(f.acceptance.length);assert.ok(f.control);assert.ok(a.catalog.journeys.some(j=>j.id===f.journey));}
  for(const j of a.catalog.journeys)for(const step of j.steps)assert.ok(a.catalog.features.some(f=>f.declaration===step));
});
test('product facets retain honest evidence and persistence boundaries',()=>{
  const {catalog:c}=generateFacets(root);
  assert.equal(c.design.components,18);assert.equal(c.design.connectors,31);
  assert.ok(c.security.every(t=>t.evidence.length>=2&&t.assessment.includes('qualitative')));
  assert.ok(c.users.measures.every(m=>m.observed===null));
  assert.ok(c.quality.every(m=>['derived','configured','requirement'].includes(m.kind)));
  assert.match(c.persistence.find(x=>x.id==='ObjectCustody').failure,/not.*durable/);
  assert.match(c.persistence.find(x=>x.id==='UnknownPublication').trust,/No timer takeover/);
  assert.match(c.persistence.find(x=>x.id==='SavedSigner').trust,/never.*automatic replacement/);
  assert.ok(c.modules.every(m=>m.declarations>0&&m.sha256.length===64));
  assert.match(c.sourceConvention,/complete UTF-8 file/);
});
test('site catalog counts actual declarations and preserves Stitch design identity',()=>{
  const {outputs,catalog:c}=generateFacets(root),site=JSON.parse(outputs.get('site/facets.json'));
  for(const f of site.facets){const m=c.modules.find(m=>m.path===f.source);assert.equal(f.count,m.declarations);assert.match(f.evidenceStatus,/required/);}
  assert.equal(c.brand.tokens.find(t=>t.name==='bg').value,'#0a0a0a');
  assert.equal(c.brand.tokens.find(t=>t.name==='panel').value,'#111111');
  assert.ok(c.brand.contrasts.every(p=>Number.isInteger(p.observedMilli)&&p.scope.includes('not whole-page')));
});
function fixture(work){const dir=mkdtempSync(resolve(tmpdir(),'stitch-facets-'));try{for(const p of ['app','src','tests','scripts','docs','vendor','product','.github','site','index.html','package.json'])cpSync(resolve(root,p),resolve(dir,p),{recursive:true});return work(dir);}finally{rmSync(dir,{recursive:true,force:true});}}
test('missing evidence files refuse generation rather than claiming coverage',()=>fixture(dir=>{
  rmSync(resolve(dir,'tests/custody.test.js'));assert.throws(()=>generateFacets(dir),/ENOENT/);
}));
test('missing action controls refuse generation rather than silently dropping a feature',()=>fixture(dir=>{
  const path=resolve(dir,'index.html');writeFileSync(path,readFileSync(path,'utf8').replace('id="dbPutBtn"','id="unknown-control"'));assert.throws(()=>generateFacets(dir),/missing action control/);
}));
test('meaningful source changes and altered type dependencies refuse stale facets',()=>fixture(dir=>{
  const path=resolve(dir,'app/src/Product/Features.lex.tex');writeFileSync(path,readFileSync(path,'utf8').replace('Browser control','Misleading control'));assert.throws(()=>checkFacets(dir),/stale output/);
  const type=resolve(dir,'app/src/Foundation/Qual.lex.tex');writeFileSync(type,readFileSync(type,'utf8')+'\n');assert.throws(()=>generateFacets(dir),/modified reference type/);
}));

test('every stakeholder has a real typed goal and journey',()=>{
  const {catalog:c}=generateFacets(root);
  c.users.groups.forEach((_,index)=>assert.ok(c.users.goals.some(g=>g.user===index)));
  assert.ok(c.journeys.some(j=>j.actor==='reader'&&j.steps.includes('Product.Features::featureLearnProtocol')));
  assert.ok(c.journeys.some(j=>j.actor==='reviewer'));
  assert.ok(c.journeys.some(j=>j.actor==='systemIntegrator'));
});
test('dangling facet references and reversed OPM edges are rejected',()=>{
  const {outputs,catalog:c}=generateFacets(root);
  const texts=new Map(c.modules.map(m=>[m.module,outputs.get(m.path)]));
  texts.set('Product.Architecture',readFileSync(resolve(root,'app/src/Product/Architecture.lex.tex'),'utf8'));
  assert.equal(validateFacetReferences(texts),true);
  const broken=new Map(texts);broken.set('Product.Features',broken.get('Product.Features').replace('\"Product.Features::callJoin\"','\"Product.Features::missingCall\"'));
  assert.throws(()=>validateFacetReferences(broken),/dangling reference/);
  const opm=new Map(texts);opm.set('Product.Design',opm.get('Product.Design').replace('kind := (ctor Foundation.Arch::OpmLinkKind.effect), source := \"Product.Architecture::storage\", target := \"Product.Design::processCommitLocal\"','kind := (ctor Foundation.Arch::OpmLinkKind.effect), source := \"Product.Design::processCommitLocal\", target := \"Product.Architecture::storage\"'));
  assert.throws(()=>validateFacetReferences(opm),/OPM direction/);
});
