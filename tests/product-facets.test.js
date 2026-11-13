import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, cpSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { generateFacets, checkFacets, validateFacetReferences, validateFacetLexicons } from '../scripts/check-facets.mjs';
import { literalRows } from '../scripts/check-product.mjs';
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
  texts.set('Foundation.Arch',readFileSync(resolve(root,'app/src/Foundation/Arch.lex.tex'),'utf8'));
  assert.equal(validateFacetReferences(texts),true);
  const broken=new Map(texts);broken.set('Product.Features',broken.get('Product.Features').replace('\"Product.Features::callJoin\"','\"Product.Features::missingCall\"'));
  assert.throws(()=>validateFacetReferences(broken),/dangling reference/);
  const opm=new Map(texts);opm.set('Product.Design',opm.get('Product.Design').replace('kind := (ctor Foundation.Arch::OpmLinkKind.effect), source := \"Product.Architecture::storage\", target := \"Product.Design::processCommitLocal\"','kind := (ctor Foundation.Arch::OpmLinkKind.effect), source := \"Product.Design::processCommitLocal\", target := \"Product.Architecture::storage\"'));
  assert.throws(()=>validateFacetReferences(opm),/OPM direction/);
});

// Authoring run 43448596054 typechecked all 38 modules but the real Prism
// projection refused PP2017. The application document omits every facet unless
// all three official packages are in the glossary closure, regardless of types.
test('application facet projection includes all official lexicons with exact upstream bytes',()=>{
  const {outputs,catalog:c}=generateFacets(root);
  const texts=new Map(c.modules.map(m=>[m.module,outputs.get(m.path)]));
  texts.set('Product.Architecture',readFileSync(resolve(root,'app/src/Product/Architecture.lex.tex'),'utf8'));
  const read=path=>readFileSync(resolve(root,path),'utf8');
  assert.equal(validateFacetLexicons(read,texts),true);
  for(const [module,packageName]of [['Product.Quality','prism.qual'],['Product.Security','prism.sec']]){
    const broken=new Map(texts);broken.set(module,broken.get(module).replace(`\\useglossary{${packageName}@1.0.0}\n`,''));
    assert.throws(()=>validateFacetLexicons(read,broken),/missing application facet lexicon closure/);
    assert.throws(()=>validateFacetLexicons(path=>path==='app/lexlean.toml'?read(path).replace(`package = "${packageName}"`,'package = "missing"'):read(path),texts),/missing application facet lexicon closure/);
  }
  assert.throws(()=>validateFacetLexicons(path=>read(path)+(path==='app/language/prism.sec/entries/sec-asset.toml'?'\n':''),texts),/modified official facet lexicon/);
  assert.ok(c.sources.some(s=>s.path==='app/lexlean.toml'));
  assert.equal(c.sources.filter(s=>/^app\/language\/prism\.(qual|sec)\//.test(s.path)).length,14);
});

test('typed projection rejects wrong-kind feature actors and steps, not just missing declarations',()=>{
  const {outputs,catalog:c}=generateFacets(root);
  const texts=new Map(c.modules.map(m=>[m.module,outputs.get(m.path)]));
  for(const module of ['Product.Architecture','Foundation.Arch'])texts.set(module,readFileSync(resolve(root,`app/src/${module.replaceAll('.','/')}.lex.tex`),'utf8'));
  const mutate=(module,from,to)=>{const result=new Map(texts);assert.ok(result.get(module).includes(from));result.set(module,result.get(module).replace(from,to));return result;};
  assert.equal(validateFacetReferences(texts),true);
  assert.throws(()=>validateFacetReferences(mutate('Product.Features','actor := "Product.Architecture::operator"','actor := "Product.Architecture::browser"')),/unresolved journey stakeholder/);
  assert.throws(()=>validateFacetReferences(mutate('Product.Features','steps := (cons "Product.Features::featureJoin"','steps := (cons "Product.Features::callJoin"')),/unresolved journey feature/);
  assert.throws(()=>validateFacetReferences(mutate('Product.Features','calls := (cons "Product.Features::callJoin" (nil String))','calls := (nil String)')),/empty feature calls/);
  assert.throws(()=>validateFacetReferences(mutate('Product.Security','componentIndex := 0','componentIndex := 999')),/unresolved asset component/);
  assert.throws(()=>validateFacetReferences(mutate('Product.Quality','requirementIndex := 0','requirementIndex := 999')),/unresolved quality requirement/);
  assert.throws(()=>validateFacetReferences(mutate('Product.Security','index := 0','index := 999')),/noncanonical facet index/);
});

test('design projection retains real architecture directions and callee ownership',()=>{
  const {outputs,catalog:c}=generateFacets(root);
  const texts=new Map(c.modules.map(m=>[m.module,outputs.get(m.path)]));
  for(const module of ['Product.Architecture','Foundation.Arch'])texts.set(module,readFileSync(resolve(root,`app/src/${module.replaceAll('.','/')}.lex.tex`),'utf8'));
  const design=texts.get('Product.Design');
  const change=fn=>{const result=new Map(texts);result.set('Product.Design',fn(design));return result;};
  const processBody='name: processAdmitObject,\n  parameters: [],\n  result: Foundation.Arch::SystemProcess,\n  body: (record Foundation.Arch::SystemProcess {owner := "Product.Architecture::storage"})';
  assert.ok(design.includes(processBody));
  assert.throws(()=>validateFacetReferences(change(text=>text.replace(processBody,processBody.replace('::storage','::admission')))),/unbacked OPM object\/process link/);
  assert.throws(()=>validateFacetReferences(change(text=>text.replace('source := "Product.Design::processCommitLocal", target := "Product.Design::processRequestPlacement"','source := "Product.Design::processRequestPlacement", target := "Product.Design::processCommitLocal"'))),/unbacked OPM invocation/);
  assert.throws(()=>validateFacetReferences(change(text=>text.replace('process := "Product.Design::processAuthorizePointer"','process := "Product.Design::processBeginWrite"'))),/UML message process owner/);
  assert.throws(()=>validateFacetReferences(change(text=>text.replace('process := "Product.Design::processDispatchDnsWrite"','process := "Product.Design::processBeginWrite"'))),/UML message process owner/);
  assert.throws(()=>validateFacetReferences(change(text=>text.replace('trigger := "Product.Design::processBeginWrite"','trigger := "Product.Design::processDispatchDnsWrite"'))),/state transition process owner/);
  const rows=literalRows(design,new Set(['Foundation.Arch::UmlMessage','Foundation.Arch::SystemProcess']));
  const owners=new Map(rows.filter(r=>r.type.endsWith('::SystemProcess')).map(r=>['Product.Design::'+r.declaration,r.owner]));
  for(const row of rows.filter(r=>r.type.endsWith('::UmlMessage')))assert.equal(owners.get(row.process),row.kind.constructor.endsWith('.reply')?row.source:row.target);
  assert.ok(rows.some(r=>r.declaration==='processAuthorizePointer'&&r.owner==='Product.Architecture::pointerAuthority'));
  assert.ok(rows.some(r=>r.declaration==='processObserveDnsRecord'&&r.owner==='Product.Architecture::runtimeHost'));
});

// Actual pinned SDK authoring run 43444521371 stopped with LLT4001 here:
// Task.feature resolves through Experience, but the nested .acceptance projection
// also needs the Feature owner in Users' direct import environment.
test('nested Feature acceptance projection directly imports its owner without weakening the obligation',()=>{
  const {outputs}=generateFacets(root);
  const users=outputs.get('app/src/Product/Users.lex.tex');
  assert.match(users,/\\importmodule\{Foundation\.Arch\}/);
  assert.match(users,/\\importmodule\{Foundation\.Experience\.V1\.Model\}/);
  assert.match(users,/\(project \(project head feature\) acceptance\)/);
  assert.match(users,/name: everyTaskNamesAcceptanceEvidence,[\s\S]*?statement: \(\(tasksHaveAcceptance \(tasks\)\) = true\),[\s\S]*?proof: decide\{\}/);
});

// Genuine pinned SDK formatter output from authoring run 43445915817.
// Keep complete match bodies exact so formatting fixes cannot weaken the predicates.
test('Users match predicates reproduce the pinned SDK canonical format',()=>{
  const users=generateFacets(root).outputs.get('app/src/Product/Users.lex.tex');
  const predicates=[
    ['goalsHaveUsers','Goal), users : Nat','(((project head user) <? users) && (goalsHaveUsers rest users))'],
    ['tasksHaveGoals','Task), count : Nat','(((project head goal) <? count) && (tasksHaveGoals rest count))'],
    ['tasksHaveAcceptance','Task)','((nonemptyAcceptance (project (project head feature) acceptance)) && (tasksHaveAcceptance rest))']
  ];
  for(const [name,parameters,branch]of predicates){
    const expected=`definition{\n  name: ${name},\n  parameters: [items : (List Foundation.Experience.V1.Model::${parameters}],\n  result: Bool,\n  body: (match items\n    | List.nil => true\n    | List.cons head rest => ${branch}),\n  recursive_argument: items\n}`;
    assert.ok(users.includes(expected),`${name} diverges from the observed SDK format`);
  }
  for(const [name,expression]of [
    ['everyGoalNamesAUser','goalsHaveUsers (goals) 4'],
    ['everyTaskNamesAGoal','tasksHaveGoals (tasks) 10'],
    ['everyTaskNamesAcceptanceEvidence','tasksHaveAcceptance (tasks)']
  ])assert.ok(users.includes(`name: ${name},\n  parameters: [],\n  statement: ((${expression}) = true),\n  proof: decide{}`));
});
