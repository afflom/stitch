#!/usr/bin/env node
/** Reproducible Stitch product facets. A source projection, never a verifier or certificate. */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { literalRows, readProduct } from './check-product.mjs';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const hash = x => createHash('sha256').update(x).digest('hex');
const sourceKappa = (path, bytes) => {
  const h=createHash('sha256');
  for(const part of [Buffer.from('prism/source-file/1'),Buffer.from(path),Buffer.from(bytes)]){const n=Buffer.alloc(8);n.writeBigUInt64BE(BigInt(part.length));h.update(n);h.update(part);}
  return h.digest('hex');
};
const q = x => JSON.stringify(x);
const cap = x => x[0].toUpperCase() + x.slice(1);
const raw = text => ({ raw: text });
const val = x => x?.raw ?? (typeof x === 'string' ? q(x) : String(x));
const list = (type, values) => values.reduceRight((rest, x) => `(cons ${val(x)} ${rest})`, `(nil ${type})`);
const record = (type, fields) => `(record ${type} {${Object.entries(fields).map(([k,v])=>`${k} := ${val(v)}`).join(', ')}})`;
const def = (name, type, body) => {
  const flat=`definition{name: ${name}, parameters: [], result: ${type}, body: ${body}}`;
  return flat.length<=100?flat+'\n':`definition{\n  name: ${name},\n  parameters: [],\n  result: ${type},\n  body: ${body}\n}\n`;
};
const row = (name, type, fields) => def(name,type,record(type,fields));
const call = name => raw(`(${name})`);
const ctor = name => raw(`(ctor ${name})`);
const structure = (name, fields) => {
  const rows=Object.entries(fields).map(([name,type])=>`{name: ${name}, type: ${type}}`);
  const array='['+rows.join(', ')+']';
  const flat=`structure{name: ${name}, type_parameters: [], parameters: [], fields: ${array}}`;
  if(flat.length<=100)return flat+'\n';
  const fieldText=('  fields: '+array).length<=100?array:'[\n'+rows.map(r=>'    '+r).join(',\n')+'\n  ]';
  return `structure{\n  name: ${name},\n  type_parameters: [],\n  parameters: [],\n  fields: ${fieldText}\n}\n`;
};
const theorem = (name, expression) => `theorem{\n  name: ${name},\n  parameters: [],\n  statement: (${expression} = true),\n  proof: decide{}\n}\n`;
const A='Foundation.Arch::', S='Foundation.Sec::', T='Production.ThreatModel::', Q='Foundation.Qual::', E='Foundation.Experience.V1.Model::';
const F='Product.Features::', D='Product.Design::';
const REF = 'https://github.com/afflom/UORust/blob/1d531dfe0120d1cbdac2dd599f6cde513118f0ce/';
const EXPERIENCE = 'app/src/Product/Experience.lex.tex';
const testsByJourney = {
  mesh: ['tests/authenticated-signaling.test.js','tests/transport-generation.test.js','tests/browser/mesh.spec.mjs'],
  objects: ['tests/custody.test.js','tests/placement-repair.test.js','tests/recovery.test.js','tests/pointer-recovery.test.js'],
  compute: ['tests/execution-identity.test.js','tests/primitive-operations.test.js','tests/runtime-admission.test.js'],
  vm: ['tests/vm-lifecycle.test.js','tests/vm-administration.test.js','tests/browser/vm.spec.mjs'],
  pointers: ['tests/dns-publication.test.js','tests/browser-authority-lifecycle.test.js','tests/browser/authority.spec.mjs'],
  resources: ['tests/runtime-admission.test.js','tests/operator-ui.test.js']
};
function fail(reason) { throw Error(`product facets: ${reason}`); }
export function validateFacetReferences(moduleTexts) {
  const declarations=new Map();
  for(const [module,text]of moduleTexts)for(const m of text.matchAll(/(?:definition|structure|inductive|theorem)\{\s*name: (\w+)/g))declarations.set(module+'::'+m[1],true);
  for(const [module,text]of moduleTexts)for(const m of text.matchAll(/"(Product\.[A-Za-z]+::[A-Za-z0-9_]+)"/g))if(!declarations.has(m[1]))fail(`dangling reference ${module} -> ${m[1]}`);
  const design=moduleTexts.get('Product.Design');
  if(design){
    const types=new Set([A+'OpmThing',A+'OpmLink',A+'UmlComponent',A+'UmlConnector',A+'UmlLifeline',A+'UmlMessage',A+'UmlState',A+'UmlTransition']);
    const rows=literalRows(design,types),subjects=new Map();
    for(const r of rows.filter(x=>x.type===A+'OpmThing'))subjects.set(r.subject,r.kind.constructor.split('.').at(-1));
    for(const r of rows.filter(x=>x.type===A+'OpmLink')){
      const kind=r.kind.constructor.split('.').at(-1),source=subjects.get(r.source),target=subjects.get(r.target);
      if(!source||!target)fail(`OPM endpoint not in view ${r.declaration}`);
      if(['agent','instrument','consumption','effect'].includes(kind)&&(source!=='object'||target!=='process'))fail(`OPM direction ${r.declaration}`);
      if(kind==='result'&&(source!=='process'||target!=='object'))fail(`OPM result direction ${r.declaration}`);
      if(kind==='invocation'&&(source!=='process'||target!=='process'))fail(`OPM invocation direction ${r.declaration}`);
    }
  }
  return true;
}
export function generateFacets(base=root) {
  const outputs=new Map(), sources=new Map(), modules=[];
  function read(path) {
    if(!/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(path)||path.split('/').includes('..'))fail(`unsafe source ${path}`);
    const bytes=readFileSync(resolve(base,path));sources.set(path,hash(bytes));return bytes.toString('utf8');
  }
  const p=readProduct(base);
  const experience=read(EXPERIENCE);
  const actions=literalRows(experience,new Set(['Action'])).sort((a,b)=>a.code-b.code);
  const journeys=literalRows(experience,new Set(['Journey']));
  if(!actions.length||new Set(actions.map(a=>a.id)).size!==actions.length)fail('empty or duplicate action catalog');
  const components=p.architecture.filter(a=>a.type===A+'Component');
  const edges=p.architecture.filter(a=>a.type===A+'Edge');
  const component=id=>{const c=components.find(c=>c.name===id);if(!c)fail(`unknown component ${id}`);return c;};
  const arch=id=>'Product.Architecture::'+component(id).declaration;
  const document=read('index.html');
  const modulePaths=[];
  function emit(name,title,imports,body,paths,records) {
    paths=[...new Set(paths)].sort();paths.forEach(read);
    const sourceRows=paths.map((path,i)=>record('Source',{record:`Product.${name}`,path,firstLine:0,lastLine:0,sha256:sources.get(path)}));
    const provenance=structure('Source',{record:'String',path:'String',firstLine:'Nat',lastLine:'Nat',sha256:'String'})+'\n'+def('sources','(List Source)',list('Source',sourceRows.map(raw)));
    const module='Product.'+name, path=`app/src/Product/${name}.lex.tex`;
    const text=`\\begin{lexlean}{${module}}\n\\useglossary{lexlean.std.bool@1.2.0}\n\\useglossary{lexlean.std.nat@1.2.0}\n\\useglossary{stitch.domain@1.0.0}\n${imports.map(i=>`\\importmodule{${i}}\n`).join('')}\\title{Stitch ${title}}\n\\begin{semanticmodule}\n${provenance}\n${body.join('\n')}\\end{semanticmodule}\n\\end{lexlean}\n`;
    outputs.set(path,text);modulePaths.push(path);modules.push({module,path,records,sourcePaths:paths});
    const id='stitch-product-'+name.toLowerCase();
    outputs.set(`app/language/stitch.domain/entries/${id}.toml`,`spec = "lexlean/entry/1"\nid = "${id}"\ncategory = "label-word"\nsurface_arity = 0\nframe = "atom"\n\n[denotation]\nkind = "document"\nmodule = "${module}"\ncomponent = "sources"\n\n[[form]]\nid = "${id}"\nchannel = "text"\nsurface = ${q('Stitch '+title)}\ncanonical_source = true\nfeatures = ["sentence-case", "singular"]\n`);
  }
  // Every existing operator action becomes a typed official Feature. Calls and
  // acceptance are declaration references, not unbound strings masquerading as IDs.
  const features=[];let body=[];
  for(const a of actions) {
    if(!journeys.some(j=>j.id===a.journey)||!testsByJourney[a.journey])fail(`unowned action ${a.id}`);
    if(!document.includes(`id="${a.control}"`))fail(`missing action control ${a.control}`);
    const suffix=a.declaration.slice('action'.length), declaration='feature'+suffix;
    const acceptance=testsByJourney[a.journey];acceptance.forEach(read);
    body.push(def('call'+suffix,'String',q(`Browser control #${a.control}: ${a.label}`)));
    body.push(def('accept'+suffix,'String',q(`Evidence to run, not a pass claim: ${acceptance.join('; ')}. Exact action guard: Product.Experience::actionAllowed code ${a.code}.`)));
    body.push(row(declaration,A+'Feature',{statement:a.label+'. '+a.help,calls:raw(list('String',[F+'call'+suffix])),acceptance:raw(list('String',[F+'accept'+suffix]))}));
    features.push({id:a.id,declaration:F+declaration,control:a.control,journey:a.journey,label:a.label,acceptance,source:EXPERIENCE,sourceDeclaration:a.declaration});
  }
  const supporting=[
    {id:'LearnProtocol',control:'encodeExample',journey:'reader',label:'Explore exact fragment recovery locally',statement:'Change the input, withhold a fragment or alter a byte using the real custody verifier; no mesh or persistence effects.',source:'site/explorer.js',acceptance:['tests/site-explorer.test.js','tests/browser/site.spec.mjs']},
    {id:'InspectFacetSources',control:'facetCatalogContent',journey:'reviewer',label:'Inspect source-derived product facets',statement:'Read declaration counts, source links and evidence boundaries without a verification badge.',source:'site/catalog.js',acceptance:['tests/site-explorer.test.js','tests/product-facets.test.js']},
    {id:'ReviewHostBoundaries',control:'docs/product-projection.md',journey:'reviewer',label:'Review whole-product host and release boundaries',statement:'Separate exact-source/native probe results from actual browser, network, VM and provider qualification.',source:'docs/product-projection.md',acceptance:['tests/source-evidence.test.js','tests/product-model.test.js']},
    {id:'ExtendProtocol',control:'docs/prism-model.md',journey:'integrator',label:'Extend source-owned protocol contracts',statement:'Locate versioned encoding dependencies, reserve-before-effect limits, replay identity and positive/negative evidence before extending adapters.',source:'docs/prism-model.md',acceptance:['tests/contracts.test.js','tests/execution-identity.test.js','tests/product-model.test.js']}
  ];
  const authority=read('src/authority-ui.js');
  const authorityIds=[...(/const controls = \{([\s\S]*?)\};/.exec(authority)?.[1]??fail('missing authority controls')).matchAll(/(\w+Btn): (\d+)/g)];
  for(const [,control,code] of authorityIds){
    const text=new RegExp(`<button[^>]*id="${control}"[^>]*>([\\s\\S]*?)<\\/button>`).exec(document)?.[1]?.replace(/<[^>]+>/g,'').trim()??fail(`missing authority control ${control}`);
    supporting.push({id:cap(control.replace(/Btn$/,'')),control,journey:'authority',label:text,statement:`Explicit origin-local operation admitted by Stitch.Authority::controlAllowed code ${code}; no new global identity, implicit trust or resolution of unknown effects.`,source:'src/authority-ui.js',acceptance:['tests/authority-ui.test.js','tests/browser-authority-lifecycle.test.js']});
  }
  for(const a of supporting){
    read(a.source);a.acceptance.forEach(read);
    if(!a.control.startsWith('docs/')&&!document.includes(`id="${a.control}"`))fail(`missing reader control ${a.control}`);
    body.push(def('call'+a.id,'String',q(a.control.startsWith('docs/')?a.control:`Browser surface #${a.control}: ${a.label}`)));
    body.push(def('accept'+a.id,'String',q('Evidence to run, not a pass claim: '+a.acceptance.join('; '))));
    body.push(row('feature'+a.id,A+'Feature',{statement:a.label+'. '+a.statement,calls:raw(list('String',[F+'call'+a.id])),acceptance:raw(list('String',[F+'accept'+a.id]))}));
    features.push({...a,declaration:F+'feature'+a.id,sourceDeclaration:'source-bound surface',operatorAction:false});
  }
  const ordered={mesh:['join'],objects:['store','PlacementRepair','RecoveryExport','RecoveryImport','RecoveryDownload'],compute:['start','resume'],vm:['boot','execute','VmReconcile','VmStop','VmDestroy'],pointers:['SaveAuthority','pin','txt','admit','publish','LoadPublication','reconcile'],resources:['export','renew']};
  const journeyRows=[];
  for(const j of journeys) {
    const ids=ordered[j.id];if(!ids)fail(`missing task order ${j.id}`);
    const steps=ids.map(id=>{const f=features.find(f=>f.id.toLowerCase()===id.toLowerCase());if(!f)fail(`unknown journey task ${j.id}/${id}`);return f.declaration;});
    const declaration='journey'+cap(j.id);body.push(row(declaration,A+'Journey',{actor:'Product.Architecture::operator',steps:raw(list('String',steps))}));
    journeyRows.push({id:j.id,declaration:F+declaration,title:j.title,summary:j.summary,steps,ordering:'Documented operator path; each step retains its own admission guard. Optional/reconciliation steps are not automatic.'});
  }
  for(const [id,actor,title,ids]of [
    ['reader','reader','Understand the Stitch protocol',['LearnProtocol','InspectFacetSources']],
    ['reviewer','reviewer','Audit evidence and assumptions',['InspectFacetSources','ReviewHostBoundaries']],
    ['integrator','systemIntegrator','Extend the protocol safely',['LearnProtocol','ReviewHostBoundaries','ExtendProtocol']],
    ['authority','operator','Care for saved identity and trust',['InspectAuthorityStorage','SaveTrustedAnchor','RestoreTrustedAnchor','ExportAuthorityJournal']]
  ]){
    const steps=ids.map(id=>{const f=features.find(f=>f.id===id);if(!f)fail(`missing supporting feature ${id}`);return f.declaration;});
    const declaration='journey'+cap(id);body.push(row(declaration,A+'Journey',{actor:'Product.Architecture::'+actor,steps:raw(list('String',steps))}));
    journeyRows.push({id,actor,declaration:F+declaration,title,summary:title+'. Each operation retains its source-owned consent and evidence boundary.',steps,ordering:'Explicit user-directed path; operations never run merely because the journey is declared.'});
  }
  body.push(def('scope','String',q('Feature acceptance names executable evidence; only a successful exact-revision run establishes its result. Journeys describe ordered available tasks, not an instruction to repeat effects.')));
  emit('Features','features and journeys',['Foundation.Arch','Product.Architecture'],body,[EXPERIENCE,'index.html',...Object.values(testsByJourney).flat(),...supporting.flatMap(r=>[r.source,...r.acceptance])],features.length+journeyRows.length);
  // Design views retain every actual component and edge. Sequence/state views
  // explain the existing DNS write-ahead protocol, not an invented runtime.
  body=[];
  const views=[['viewComponents','Five-layer browser component relationships','umlComponent'],['viewObjectProcess','Recoverable object process','opmObjectProcess'],['viewPublicationSequence','Scoped publication and read-only reconciliation','umlSequence'],['viewPublicationState','Unknown writes are never repeated','umlStateMachine']];
  for(const [id,title,kind] of views)body.push(row(id,A+'DesignView',{title,viewpoint:'Product.Architecture::productViewpoint',diagram:ctor(A+'DesignDiagram.'+kind)}));
  for(const c of components)body.push(row('component'+cap(c.name),A+'UmlComponent',{view:D+'viewComponents',component:arch(c.name)}));
  for(const e of edges)body.push(row('connector'+cap(e.declaration),A+'UmlConnector',{view:D+'viewComponents',edge:'Product.Architecture::'+e.declaration}));
  const processes=[['Admit','admission'],['CommitLocal','storage'],['RequestPlacement','transport'],['CheckReceipt','storage'],['Recover','storage'],['BeginWrite','discovery'],['Reconcile','discovery'],['Confirm','discovery'],['Refuse','discovery'],['RetainUnknown','discovery']];
  for(const [name,owner]of processes)body.push(row('process'+name,A+'SystemProcess',{owner:arch(owner)}));
  for(const id of ['identity','storage','peers'])body.push(row('object'+cap(id),A+'OpmThing',{view:D+'viewObjectProcess',kind:ctor(A+'OpmThingKind.object'),subject:arch(id)}));
  for(const [name]of processes.slice(0,5))body.push(row('opm'+name,A+'OpmThing',{view:D+'viewObjectProcess',kind:ctor(A+'OpmThingKind.process'),subject:D+'process'+name}));
  const opmLinks=[['instrument','objectIdentity','opmAdmit'],['invocation','opmAdmit','opmCommitLocal'],['effect','objectStorage','opmCommitLocal'],['invocation','opmCommitLocal','opmRequestPlacement'],['instrument','objectPeers','opmCheckReceipt'],['invocation','opmCheckReceipt','opmRecover'],['effect','objectStorage','opmRecover']];
  opmLinks.forEach(([kind,source,target],i)=>body.push(row('opmLink'+i,A+'OpmLink',{view:D+'viewObjectProcess',kind:ctor(A+'OpmLinkKind.'+kind),source:source.startsWith('object')?arch(source.slice(6).replace(/^./,c=>c.toLowerCase())):D+'process'+source.slice(3),target:target.startsWith('object')?arch(target.slice(6).replace(/^./,c=>c.toLowerCase())):D+'process'+target.slice(3)})));
  ['browser','discovery','pointerAuthority','runtimeHost'].forEach((id,i)=>body.push(row('lifeline'+cap(id),A+'UmlLifeline',{view:D+'viewPublicationSequence',component:arch(id),order:i})));
  const messages=[['browser','discovery','BeginWrite','synchronous'],['discovery','pointerAuthority','Admit','synchronous'],['discovery','runtimeHost','BeginWrite','asynchronous'],['runtimeHost','discovery','RetainUnknown','reply'],['browser','discovery','Reconcile','synchronous'],['discovery','runtimeHost','Reconcile','asynchronous'],['runtimeHost','discovery','Confirm','reply']];
  messages.forEach(([source,target,process,kind],i)=>body.push(row('message'+i,A+'UmlMessage',{view:D+'viewPublicationSequence',kind:ctor(A+'UmlMessageKind.'+kind),order:i,source:arch(source),target:arch(target),process:D+'process'+process})));
  const effects=read('app/src/Stitch/Effects.lex.tex');
  const phaseText=/name: DnsPhase,[\s\S]*?constructors: \[([\s\S]*?)\n  \]/.exec(effects)?.[1]??fail('missing DnsPhase');
  const states=[...phaseText.matchAll(/name: (\w+), fields: \[\]/g)].map(m=>m[1]);
  for(const state of states){body.push(row('state'+state,A+'SystemState',{owner:arch('discovery')}));body.push(row('uml'+state,A+'UmlState',{view:D+'viewPublicationState',state:D+'state'+state,initial:state==='Idle'}));}
  const transitions=[['Idle','Unknown','BeginWrite'],['Published','Unknown','BeginWrite'],['Refused','Unknown','BeginWrite'],['Unknown','Published','Confirm'],['Unknown','Published','Reconcile'],['Unknown','Refused','Refuse'],['Unknown','Unknown','RetainUnknown']];
  transitions.forEach(([source,target,trigger],i)=>{if(!states.includes(source)||!states.includes(target))fail('unknown DNS state');body.push(row('transition'+i,A+'UmlTransition',{view:D+'viewPublicationState',order:i,source:D+'state'+source,target:D+'state'+target,trigger:D+'process'+trigger}));});
  body.push(def('boundary','String',q('Design relationships are views of existing contracts. Transition edges remain conditional on Stitch.Effects predicates and exact host observations. They neither execute effects nor prove the host implements every transition.')));
  const design={components:components.length,connectors:edges.length,views:views.map(([id,title,diagram])=>({id,title,diagram})),states,transitions};
  emit('Design','protocol design views',['Foundation.Arch','Product.Architecture'],body,['app/src/Product/Architecture.lex.tex','app/src/Product/Model.lex.tex','app/src/Stitch/Effects.lex.tex','docs/prism-model.md','docs/lifecycle-effects.md'],components.length+edges.length+views.length+states.length+transitions.length+messages.length+opmLinks.length+processes.length);
  // Security assesses attack opportunity and consequence qualitatively. These
  // categories are design assessments, never frequencies or measured scores.
  const threatRows=[
    ['AuthoritySpoofing','pointerAuthority','spoofing','high','critical','An arbitrary valid self-signature is mistaken for an independently pinned writer.','Exact independently accepted key/name/head; strict successor CAS and revocation gates.','tests/browser-authority-lifecycle.test.js','docs/browser-authority.md'],
    ['CheckpointForgery','compute','tampering','high','major','A hashed but impossible state is accepted as computation.','Replay exact program/input/execution identity before accepting or resuming.','tests/execution-identity.test.js','docs/uor-primitives.md'],
    ['Disclosure','publicRelay','informationDisclosure','high','major','A mesh topic or relay is mistaken for private storage.','Separate public signaling and payload-relay consent; explicit disclosure and no privacy claim.','tests/relay-framing.test.js','docs/relay-framing.md'],
    ['EffectReplay','discovery','repudiation','medium','major','An unknown DNS write is repeated after restart or key rotation.','Strict write-ahead intent and exact read-only reconciliation; unknown journal retention.','tests/dns-publication.test.js','docs/lifecycle-effects.md'],
    ['FragmentTampering','storage','tampering','high','major','A holder supplies modified, duplicate-index or wrong-manifest bytes.','Full domain-separated commitments and exact compatible indexed recovery.','tests/custody.test.js','docs/prism-model.md'],
    ['GuestPrivilege','vm','elevationOfPrivilege','medium','critical','Guest output is mistaken for trusted execution or broad host authority.','Separate VM effects, bounded mounts and explicit lifecycle/command reconciliation.','tests/vm-administration.test.js','docs/vm-administration.md'],
    ['OriginCompromise','browser','elevationOfPrivilege','medium','critical','Malicious same-origin code can use retained key handles and read local data.','Source/asset inventory and origin boundary; nonextractability is not protection from active same-origin code.','tests/source-evidence.test.js','docs/browser-authority.md'],
    ['ResourceExhaustion','admission','denialOfService','high','major','Untrusted messages, replay or unknown effects exhaust application allowances.','Reserve each independent resource before effects; unknown outcomes stay charged.','tests/runtime-admission.test.js','docs/prism-model.md'],
    ['SignalingSpoofing','transport','spoofing','high','major','A relay replays or substitutes SDP/ICE and stale session callbacks.','Signed exact signaling, session/generation fencing and bounded channel flow.','tests/authenticated-signaling.test.js','docs/authenticated-signaling.md'],
    ['StorageLoss','storage','denialOfService','medium','major','Tab loss or eviction removes the only object fragments or recent trust anchor.','Explicit recovery export and origin-storage evidence; no guarantee after total information loss.','tests/recovery.test.js','docs/recovery.md'],
    ['VendorSubstitution','vm','tampering','medium','critical','Loaded emulator, BIOS or guest differs from reviewed inventory.','Retained corresponding-source materials and exact local asset digests; live load-time remote integrity remains an assumption.','tests/guest-qualification.test.js','docs/vendor-provenance.md']
  ];
  const assetIds=[...new Set(threatRows.map(r=>r[1]))].sort();
  const security=threatRows.map(([id,asset,category,likelihood,impact,threat,control,test,source],index)=>({id,asset,category,likelihood,impact,threat,control,evidence:[test,source],index,assessment:'Conservative qualitative design assessment. High: directly supplied adversarial input; medium: environmental/host privilege or failure required. Impact describes possible consequence, not probability.'}));
  body=[def('assessmentPolicy','String',q('Likelihood and impact are explicit conservative qualitative engineering assessments, not observed probabilities, numeric risk scores or certification. Named gates are evidence procedures, not assertions that a run passed. Residual host/crypto/storage assumptions remain open.'))];
  assetIds.forEach((id,i)=>{body.push(row('asset'+cap(id),S+'Asset',{index:i,componentIndex:component(id).index}));body.push(row('modeledAsset'+cap(id),T+'ModeledAsset',{asset:'Product.Security::asset'+cap(id),name:id,text:component(id).text}));});
  security.forEach(r=>{
    for(const path of r.evidence)read(path);
    body.push(row('threat'+r.id,S+'Threat',{index:r.index}));
    body.push(row('risk'+r.id,S+'Risk',{index:r.index,assetIndex:assetIds.indexOf(r.asset),threatIndex:r.index,likelihood:ctor(S+'Likelihood.'+r.likelihood),impact:ctor(S+'Impact.'+r.impact)}));
    body.push(row('control'+r.id,S+'ApplicationSecurityControl',{index:r.index,riskIndex:r.index}));
    body.push(row('activity'+r.id,S+'SecurityActivity',{index:r.index,controlIndex:r.index}));
    body.push(row('modeledThreat'+r.id,T+'ModeledThreat',{threat:'Product.Security::threat'+r.id,name:r.id,text:r.threat,category:ctor(T+'Stride.'+r.category)}));
    const evidence=r.evidence.map((path,i)=>raw(record(T+'Evidence',{kind:ctor(T+'EvidenceKind.'+(i?'review':'gate')),reference:path})));
    body.push(row('modeledControl'+r.id,T+'ModeledControl',{control:'Product.Security::control'+r.id,name:r.id,text:r.control,evidence:raw(list(T+'Evidence',evidence))}));
    body.push(row('mapping'+r.id,T+'ThreatMapping',{threat:'Product.Security::threat'+r.id,controls:raw(list('String',['Product.Security::control'+r.id]))}));
  });
  body.push(row('controlSet',T+'ControlSet',{title:'Stitch scoped adversarial boundaries',text:'Traceable prevention, refusal and recovery procedures; residual assumptions are retained in Product.Model.',version:JSON.parse(read('package.json')).version,lastModified:'2026-11-13T00:00:00Z'}));
  emit('Security','security and threat model',['Foundation.Sec','Production.ThreatModel','Product.Architecture'],body,['app/src/Product/Model.lex.tex','app/src/Product/Architecture.lex.tex','package.json',...security.flatMap(r=>r.evidence)],security.length*7+assetIds.length*2+1);
  // Measurable limits come from the implementation; zero-defect obligations are
  // requirements, not observations. Unmeasured browser/field qualities stay open.
  const replay=read('src/layer4-compute/replay.js');
  const constant=name=>{const m=new RegExp(`export const ${name} = (\\d+);`).exec(replay);if(!m)fail(`missing source bound ${name}`);return Number(m[1]);};
  const quality=[
    {id:'ActionCoverage',characteristic:'FunctionalSuitability',sub:'FunctionalCompleteness',threshold:actions.length,unit:'modeled actions',method:'Count Product.Experience Action definitions, require one official Feature per action.',source:EXPERIENCE,evidence:'tests/product-facets.test.js',kind:'derived'},
    {id:'ComponentCoverage',characteristic:'Maintainability',sub:'Modularity',threshold:components.length,unit:'components',method:'Every actual architecture component is represented in the design view.',source:'app/src/Product/Architecture.lex.tex',evidence:'tests/product-facets.test.js',kind:'derived'},
    {id:'ProgramInstructions',characteristic:'PerformanceEfficiency',sub:'Capacity',threshold:constant('MAX_PROGRAM_STEPS'),unit:'instructions',method:'Configured acceptance ceiling, not observed capacity or performance.',source:'src/layer4-compute/replay.js',evidence:'tests/primitive-operations.test.js',kind:'configured'},
    {id:'ProgramWork',characteristic:'PerformanceEfficiency',sub:'Capacity',threshold:constant('MAX_PROGRAM_WORK'),unit:'abstract work units',method:'Model-derived work charged before replay; does not meter VM/browser/TLS overhead.',source:'src/layer4-compute/replay.js',evidence:'tests/runtime-admission.test.js',kind:'configured'},
    {id:'TermWidth',characteristic:'PerformanceEfficiency',sub:'Capacity',threshold:constant('MAX_TERM_BITS'),unit:'bits',method:'Explicit parsing/memory envelope, not an upstream ring semantic limit.',source:'src/layer4-compute/replay.js',evidence:'tests/primitive-operations.test.js',kind:'configured'},
    {id:'ForgedCheckpoints',characteristic:'Security',sub:'Integrity',threshold:0,unit:'accepted impossible checkpoints',method:'Zero-defect requirement exercised by adversarial replay tests.',source:'docs/prism-model.md',evidence:'tests/execution-identity.test.js',kind:'requirement'},
    {id:'UnknownWriteReplay',characteristic:'Reliability',sub:'Recoverability',threshold:0,unit:'blind retries of unknown DNS writes',method:'Unknown publication permits read-only reconciliation, never another mutation.',source:'docs/browser-authority.md',evidence:'tests/dns-publication.test.js',kind:'requirement'},
    {id:'AuthorityRollback',characteristic:'Security',sub:'Authenticity',threshold:0,unit:'accepted stale or foreign trust transitions',method:'Exact saved head comparison and independent writer/digest acceptance.',source:'docs/browser-authority.md',evidence:'tests/browser-authority-lifecycle.test.js',kind:'requirement'},
    {id:'SilentEvidencePromotion',characteristic:'InteractionCapability',sub:'SelfDescriptiveness',threshold:0,unit:'unknown host outcomes displayed as verified',method:'Persistent evidence labels distinguish digest, replay, unknown effects and unqualified hosts.',source:EXPERIENCE,evidence:'tests/product-experience.test.js',kind:'requirement'},
    {id:'SourceDrift',characteristic:'Maintainability',sub:'Testability',threshold:0,unit:'unregenerated model or facet outputs',method:'Regeneration must reproduce committed output bytes.',source:'scripts/check-facets.mjs',evidence:'tests/product-facets.test.js',kind:'requirement'}
  ].sort((a,b)=>a.id.localeCompare(b.id,'en'));
  const characteristics=[...new Set(quality.map(x=>x.characteristic))].sort(),subs=[...new Set(quality.map(x=>x.sub))].sort();body=[];
  characteristics.forEach((name,index)=>body.push(row('characteristic'+name,Q+'ProductQualityCharacteristic',{index})));
  subs.forEach((name,index)=>body.push(row('subcharacteristic'+name,Q+'QualitySubcharacteristic',{index,characteristicIndex:characteristics.indexOf(quality.find(x=>x.sub===name).characteristic)})));
  body.push(structure('MeasureContract',{requirement:'String',unit:'String',method:'String',source:'String',evidence:'String',kind:'String',observed:'Bool'}));
  quality.forEach((r,index)=>{body.push(row('requirement'+r.id,Q+'QualityRequirement',{index,subcharacteristicIndex:subs.indexOf(r.sub)}));body.push(row('measure'+r.id,Q+'QualityMeasure',{index,requirementIndex:index,threshold:r.threshold}));body.push(row('contract'+r.id,'MeasureContract',{requirement:'Product.Quality::requirement'+r.id,unit:r.unit,method:r.method,source:r.source,evidence:r.evidence,kind:r.kind,observed:false}));});
  body.push(def('openQualities','(List String)',list('String',['Physical NAT topology coverage and independent failure domains','Eviction/device-loss durability','Accessibility across supported assistive technologies','User comprehension, task completion time and satisfaction','Whole-host refinement and native artifact acceptance on the exact release revision'])));
  emit('Quality','quality requirements and open measurements',['Foundation.Qual'],body,[...quality.flatMap(r=>[r.source,r.evidence])],quality.length*3+characteristics.length+subs.length);
  // Existing Stitch identity is the source of the experience layer: no borrowed
  // characters, palette, account issuer or brand promise.
  const css=/\s*:root\s*\{([^}]+)\}/.exec(document)?.[1]??fail('missing Stitch token source');
  const tokens=[...css.matchAll(/--([a-z-]+):\s*([^;]+);/g)].map(m=>({name:m[1],value:m[2].trim(),type:m[2].trim().startsWith('#')?'color':'fontFamily',source:'index.html'}));
  const readerCss=read('site/site.css');
  const readerRoot=/:root\s*\{([^}]+)\}/.exec(readerCss)?.[1]??fail('missing reader token source');
  tokens.push(...[...readerRoot.matchAll(/--([a-z-]+):\s*([^;]+);/g)].map(m=>({name:m[1],value:m[2].trim(),type:m[2].trim().startsWith('#')?'color':'fontFamily',source:'site/site.css'})));
  if(new Set(tokens.map(t=>t.name)).size!==tokens.length)fail('duplicate design token');
  if(!['bg','panel','fg','muted','font'].every(n=>tokens.some(t=>t.name===n)))fail('incomplete Stitch palette');
  const rgb=hex=>[1,3,5].map(i=>parseInt(hex.slice(i,i+2),16)/255);
  const lum=hex=>rgb(hex).map(c=>c<=0.04045?c/12.92:((c+0.055)/1.055)**2.4).reduce((v,c,i)=>v+c*[0.2126,0.7152,0.0722][i],0);
  const contrasts=[['fg','bg'],['fg','panel'],['muted','panel'],['accent','bg'],['site-muted','bg']].map(([fg,bg])=>{
    const a=lum(tokens.find(t=>t.name===fg).value),b=lum(tokens.find(t=>t.name===bg).value);
    return {foreground:fg,background:bg,observedMilli:Math.floor((Math.max(a,b)+0.05)/(Math.min(a,b)+0.05)*1000),requiredMilli:4500,scope:'Declared opaque text colors only; not whole-page WCAG conformance.'};
  });
  const promise=JSON.parse(read('package.json')).description;
  const brand={name:'Stitch',promise,tokens,contrasts,scope:'Stitch own dark technical surface, monospace operator workbench and source-owned reader accent palette. No inherited Prism-DevRel or UORust character or theme.'};
  body=[row('authority',E+'Authority',{framework:'Wheeler brand identity; W3C Design Tokens; WCAG 2.2 SC 1.4.3 for the listed opaque text pairs only',repository:'https://github.com/Syntra-Labs/stitch',commit:'the exact revision of the cited sources'})];
  const brandSources=['index.html','package.json','site/site.css'];
  body.push(def('brandSources',`(List ${E}Source)`,list(E+'Source',brandSources.map(path=>raw(record(E+'Source',{record:'Product.Brand',path,firstLine:0,lastLine:0,kappa:sourceKappa(path,read(path))}))))));
  body.push(def('elements',`(List ${E}BrandElement)`,list(E+'BrandElement',[
    raw(record(E+'BrandElement',{kind:ctor(E+'BrandElementKind.productName'),text:'Stitch',source:1})),
    raw(record(E+'BrandElement',{kind:ctor(E+'BrandElementKind.productPromise'),text:promise,source:1})),
    raw(record(E+'BrandElement',{kind:ctor(E+'BrandElementKind.typography'),text:tokens.find(t=>t.name==='font').value,source:0})),
    raw(record(E+'BrandElement',{kind:ctor(E+'BrandElementKind.palette'),text:tokens.filter(t=>t.type==='color').map(t=>`${t.name} ${t.value}`).join('; '),source:0}))
  ])));
  body.push(def('tokens',`(List ${E}DesignToken)`,list(E+'DesignToken',tokens.map(t=>raw(record(E+'DesignToken',{name:t.name,type:ctor(E+'TokenType.'+t.type),value:t.value,hex:t.type==='color'?t.value:'',source:brandSources.indexOf(t.source)}))))));
  body.push(def('contrasts',`(List ${E}ContrastPair)`,list(E+'ContrastPair',contrasts.map(c=>raw(record(E+'ContrastPair',{foreground:tokens.findIndex(t=>t.name===c.foreground),background:tokens.findIndex(t=>t.name===c.background),backgroundAlphaMilli:1000,criterion:ctor(E+'ContrastCriterion.text'),observedMilli:c.observedMilli,requiredMilli:c.requiredMilli,source:0}))))));
  body.push(def('contrastScope','String',q('These are arithmetic observations over the listed declared opaque text pairs. Focus, disabled states, overlays, browser rendering, user agents and assistive technologies need independent checks. A missing or failing pair cannot establish whole-page accessibility.')));
  emit('Brand','brand and design system',['Foundation.Experience.V1.Model'],body,brandSources,4+tokens.length+contrasts.length);
  // Context of use connects real stakeholder declarations to meaningful paths.
  // Test inventory and task counts are not usability observations.
  const stakeholders=p.architecture.filter(x=>x.type===A+'Stakeholder').sort((a,b)=>a.index-b.index);
  body=[row('authority',E+'Authority',{framework:'ISO 9241-11 context of use and ISO 9241-210 human-centred design',repository:'https://github.com/Syntra-Labs/stitch',commit:'the exact revision of the cited sources'})];
  body.push(def('groups',`(List ${E}UserGroup)`,list(E+'UserGroup',stakeholders.map(s=>raw(record(E+'UserGroup',{stakeholder:call('Product.Architecture::'+s.declaration),characteristics:s.text}))))));
  const goals=journeyRows.map(j=>({user:stakeholders.find(s=>s.declaration===(j.actor??'operator'))?.index??fail(`unknown journey actor ${j.actor}`),journey:j.declaration,outcome:j.summary,id:j.id,steps:j.steps}));
  body.push(def('goals',`(List ${E}Goal)`,list(E+'Goal',goals.map(g=>raw(record(E+'Goal',{user:g.user,journey:call(g.journey),outcome:g.outcome}))))));
  const tasks=goals.flatMap((g,i)=>g.steps.map((feature,order)=>({goal:i,order,feature})));
  body.push(def('tasks',`(List ${E}Task)`,list(E+'Task',tasks.map(t=>raw(record(E+'Task',{goal:t.goal,order:t.order,feature:call(t.feature)}))))));
  body.push(def('environments',`(List ${E}Environment)`,list(E+'Environment',['browser','runtimeHost','peers','staticHost'].map(id=>raw(record(E+'Environment',{kind:ctor(E+'EnvironmentKind.technical'),component:call(arch(id))}))))));
  const measures=goals.flatMap((_,goal)=>['effectiveness','efficiency','satisfaction'].map(outcome=>({goal,outcome,observed:null,method:'open: no user study on this exact product revision; acceptance tests and task counts are not usability observations'})));
  body.push(def('measures',`(List ${E}UsabilityMeasure)`,list(E+'UsabilityMeasure',measures.map(m=>raw(record(E+'UsabilityMeasure',{goal:m.goal,outcome:ctor(E+'UsabilityOutcome.'+m.outcome),observed:raw('(ctor Option.none [Nat])'),method:m.method}))))));
  body.push(def('contextNotes','(List String)',list('String',[
    'Reader: explain object identity, fragment reconstruction, custody conditions and pure replay before mesh participation; no user comprehension result is asserted.',
    'Reviewer: inspect source-bound facet catalog, exact verification artifacts and residual assumptions; a source inventory is not a proof result.',
    'System integrator: locate five-layer contracts, action guards, host effects and extension boundaries without inferring durable storage or consensus.'
  ])));
  const users={groups:stakeholders.map(s=>({id:s.declaration,characteristics:s.text})),goals,tasks,measures};
  body.push(`definition{\n  name: goalsHaveUsers,\n  parameters: [items : (List ${E}Goal), users : Nat],\n  result: Bool,\n  body: (match items | List.nil => true | List.cons head rest => (((project head user) <? users) && (goalsHaveUsers rest users))),\n  recursive_argument: items\n}\n`);
  body.push(`definition{\n  name: tasksHaveGoals,\n  parameters: [items : (List ${E}Task), count : Nat],\n  result: Bool,\n  body: (match items | List.nil => true | List.cons head rest => (((project head goal) <? count) && (tasksHaveGoals rest count))),\n  recursive_argument: items\n}\n`);
  body.push(`definition{\n  name: nonemptyAcceptance,\n  parameters: [items : (List String)],\n  result: Bool,\n  body: (match items | List.nil => false | List.cons head rest => true)\n}\n`);
  body.push(`definition{\n  name: tasksHaveAcceptance,\n  parameters: [items : (List ${E}Task)],\n  result: Bool,\n  body: (match items | List.nil => true | List.cons head rest => ((nonemptyAcceptance (project (project head feature) acceptance)) && (tasksHaveAcceptance rest))),\n  recursive_argument: items\n}\n`);
  body.push(theorem('everyGoalNamesAUser',`(goalsHaveUsers (goals) ${stakeholders.length})`));
  body.push(theorem('everyTaskNamesAGoal',`(tasksHaveGoals (tasks) ${goals.length})`));
  body.push(theorem('everyTaskNamesAcceptanceEvidence','(tasksHaveAcceptance (tasks))'));
  emit('Users','context of use and usability',['Foundation.Arch','Foundation.Experience.V1.Model','Product.Architecture','Product.Features'],body,['app/src/Product/Architecture.lex.tex',EXPERIENCE,'docs/operator-experience.md'],stakeholders.length+goals.length+tasks.length+measures.length+4);
  // Persistence inventory exposes what automation can restore without creating
  // trust, dropping unknown writes, or pretending volatile bytes are durable.
  const persistence=[
    {id:'SavedSigner',storage:'Origin IndexedDB nonextractable CryptoKey',restore:'Startup restores only a valid active existing record.',automatic:true,trust:'Missing, malformed or revoked records never authorize automatic replacement.',failure:'Origin eviction or device loss can destroy the only key.',source:'src/layer1-uor/browser-authority.js',evidence:'tests/browser-authority.test.js'},
    {id:'TrustedHead',storage:'Origin IndexedDB exact name/key/digest with history',restore:'Admitted successors persist by exact CAS before the live head changes; live restore is explicit.',automatic:false,trust:'Independent exact key and recent digest acceptance is not derived from a self-signature.',failure:'Storage failure preserves the previous live head; total loss requires independent recent evidence.',source:'src/layer1-uor/browser-authority.js',evidence:'tests/pointer-recovery.test.js'},
    {id:'UnknownPublication',storage:'Origin IndexedDB strict write-ahead intent',restore:'Load the exact scoped candidate and perform read-only reconciliation.',automatic:false,trust:'No timer takeover, blind retry or deletion of unresolved intent.',failure:'An absent provider read does not prove the old mutation never occurred.',source:'src/layer1-uor/browser-authority.js',evidence:'tests/dns-publication.test.js'},
    {id:'ObjectCustody',storage:'Session RAM plus conditionally reachable peer fragments',restore:'Automatically verify received bytes; repair only within admitted budgets and checked receipts.',automatic:true,trust:'Different peer IDs do not prove failure-domain independence or future retention.',failure:'All-byte loss cannot be repaired; local storage persistence does not make object cache durable.',source:'src/layer3-storage/custody.js',evidence:'tests/placement-repair.test.js'},
    {id:'PureCheckpoint',storage:'Session state or explicitly exported recovery bundle',restore:'Every received checkpoint is replayed against its exact program/input/execution identity.',automatic:true,trust:'Replay does not grant exclusive execution or prove arbitrary guest effects.',failure:'Older execution identities are refused without explicit revalidation.',source:'src/layer4-compute/replay.js',evidence:'tests/execution-identity.test.js'},
    {id:'RecoveryVault',storage:'Session-only checked vault and user-saved external file',restore:'Verify complete bundle atomically; export strips accepted-trust status.',automatic:false,trust:'Imported keys and anchors are supplied evidence, not trusted authority.',failure:'External export is not a durability certificate; stale/conflicting imports refuse.',source:'src/recovery.js',evidence:'tests/recovery.test.js'},
    {id:'BudgetLedger',storage:'Session-local epochs plus explicit history export',restore:'Unknown effects remain charged; renewal is a deliberate new allowance.',automatic:false,trust:'No automatic refund or epoch rollover.',failure:'Browser reload is not durable preservation of the budget ledger.',source:'src/layer2-schedulers/policy.js',evidence:'tests/runtime-admission.test.js'},
    {id:'VmCommand',storage:'Retained host command handles and observed lifecycle',restore:'Observe the selected old command result without dispatching it again.',automatic:false,trust:'A timeout is an unknown outcome, not cancellation or rollback.',failure:'Stop/destroy are pending until host confirmation; external effects are not reversible.',source:'src/layer4-compute/vm-administration.js',evidence:'tests/vm-administration.test.js'}
  ];
  body=[structure('Mechanism',{id:'String',storage:'String',restore:'String',automatic:'Bool',trust:'String',failure:'String',source:'String',evidence:'String'})];
  persistence.forEach(r=>body.push(row('mechanism'+r.id,'Mechanism',r)));
  body.push(def('mechanisms','(List Mechanism)',list('Mechanism',persistence.map(r=>call('mechanism'+r.id)))));
  body.push(`definition{\n  name: restoreExistingSignerAllowed,\n  parameters: [present : Bool, valid : Bool, revoked : Bool, storageAvailable : Bool],\n  result: Bool,\n  body: (present && (valid && ((not revoked) && storageAvailable)))\n}\n`);
  body.push(`theorem{\n  name: absentSignerIsNeverRestored,\n  parameters: [],\n  statement: (forall (valid : Bool), (forall (revoked : Bool), (forall (available : Bool), ((restoreExistingSignerAllowed false valid revoked available) = false)))),\n  proof: decide{}\n}\n`);
  body.push(`theorem{\n  name: revokedSignerIsNeverRestored,\n  parameters: [],\n  statement: (forall (present : Bool), (forall (valid : Bool), (forall (available : Bool), ((restoreExistingSignerAllowed present valid true available) = false)))),\n  proof: decide{}\n}\n`);
  body.push(theorem('unknownPublicationRetainsReadOnlyBoundary','(not (Stitch.Effects::dnsMayWritePhase (ctor Stitch.Effects::DnsPhase.Unknown)))'));
  body.push(theorem('unknownPublicationOffersReconciliation','(Stitch.Effects::dnsMayReconcile (ctor Stitch.Effects::DnsPhase.Unknown))'));
  body.push(def('identitySeparation','String',q('Object commitments, peer transport keys, saved Ed25519 name authority and human account identity are distinct. No new account issuer, passkey registry, cross-device trust synchronization or private-key backup is implemented by these facets.')));
  emit('Persistence','identity persistence and safe automation',['Stitch.Effects'],body,[...persistence.flatMap(r=>[r.source,r.evidence]),'docs/browser-authority.md','docs/recovery.md'],persistence.length);
  const release={version:JSON.parse(read('package.json')).version,deployments:p.deployments.map(d=>({id:d.id,entry:d.entry,requiredCapabilities:d.requiredCapabilities})),assets:p.assets.map(a=>({path:a.path,source:a.source??'',licenseStatus:a.licenseStatus,redistributionCleared:a.redistributionCleared})),gate:'.github/workflows/prism.yml',boundary:'Static publication, source verification, native artifact acceptance and browser qualification are distinct. This inventory reports no current pass result.'};
  body=[structure('Artifact',{path:'String',licenseStatus:'String',materialsRecorded:'Bool'}),structure('Deployment',{id:'String',entry:'String',capabilities:'(List String)'}),def('version','String',q(release.version))];
  release.assets.forEach((a,i)=>body.push(row('artifact'+String(i).padStart(3,'0'),'Artifact',{path:a.path,licenseStatus:a.licenseStatus,materialsRecorded:a.redistributionCleared})));
  release.deployments.forEach(d=>body.push(row('deployment'+cap(d.id),'Deployment',{id:d.id,entry:d.entry,capabilities:raw(list('String',d.requiredCapabilities))})));
  body.push(def('gate','String',q(release.gate)));body.push(def('releaseBoundary','String',q(release.boundary)));
  body.push(def('releaseRequirements','(List String)',list('String',[
    'Regenerate source bindings, every product facet and the exact product artifact inventory before qualification.',
    'Run exact pinned LexLean source/lock checks, Lean and leanchecker with observed axiom policy; retain original verifier records.',
    'Run full pinned PrismPM native artifact and acceptance-vector gates; source-only acceptance does not replace them.',
    'Run runtime, independent custody vectors, Rust conformance and actual Chromium workflows on the submitted revision.',
    'Publish the complete same-origin UI and dependency set with source/license materials; do not replace the product with its pure probe.',
    'Rollback uses a complete prior asset set and retains unknown-effect journals. Browser/provider/NAT assumptions and unsupported platforms remain explicit.'
  ])));
  emit('Release','release and deployment contract',[],body,['package.json','app/src/Product/Model.lex.tex','.github/workflows/prism.yml','vendor/distribution.json','docs/product-projection.md','docs/vendor-provenance.md'],release.assets.length+release.deployments.length);
  const compliance=[
    ['Architecture','ISO/IEC/IEEE 42010','Represent every component, flow, stakeholder and concern with traceable viewpoints.','app/src/Product/Architecture.lex.tex','scripts/check-product.mjs'],
    ['Design','ISO/PAS 19450 and UML 2.5.1','Provide OPM object/process and UML component, sequence and state-machine views; views remain conditional on real domain predicates.','app/src/Product/Design.lex.tex','scripts/check-facets.mjs'],
    ['Features','Prism official feature and journey facets','Every existing action has a declared call and named acceptance evidence; each journey names declared features.','app/src/Product/Features.lex.tex','tests/product-facets.test.js'],
    ['ThreatModel','ISO 27034, ISO 27005 and STRIDE','Give every threat a traceable control/evidence path while retaining qualitative assessment and residual host assumptions.','app/src/Product/Security.lex.tex','tests/product-facets.test.js'],
    ['Quality','ISO/IEC 25010:2023','Distinguish source-derived counts, configured limits, zero-defect obligations and unmeasured observations.','app/src/Product/Quality.lex.tex','tests/product-facets.test.js'],
    ['CanonicalBytes','RFC 8785','Canonical JSON and framed commitments are checked at byte boundaries.','docs/canonical-json.md','tests/canonical-json.test.js'],
    ['Dns','RFC 1035, RFC 8484 and provider contracts','DNS wire decoding and full multipart pointer publication retain exact scope and unknown-effect reconciliation.','docs/dns-client.md','tests/dns-wire.test.js'],
    ['IdentityPersistence','Origin storage and WebCrypto contracts','Restore only existing active saved identity; do not infer trust from supplied data or recover keys after total loss.','docs/browser-authority.md','tests/browser-authority-lifecycle.test.js'],
    ['ContextOfUse','ISO 9241-11 and ISO 9241-210','Connect stakeholders to goals, tasks and environments; unmeasured effectiveness, efficiency and satisfaction remain open.','app/src/Product/Users.lex.tex','tests/product-facets.test.js'],
    ['Brand','Wheeler; W3C Design Tokens; scoped WCAG 2.2 measurements','Preserve Stitch identity and source its design tokens. Listed contrast measurements are not whole-page accessibility conformance.','app/src/Product/Brand.lex.tex','tests/product-facets.test.js'],
    ['Distribution','Dependency source and license obligations','Keep exact asset identity and accompanying materials, separately from security/qualification evidence.','docs/vendor-provenance.md','tests/guest-qualification.test.js'],
    ['Release','Pinned SDK and exact-revision acceptance','Source, native artifact, runtime, hosted browser and field qualification are distinct gates.','docs/product-projection.md','.github/workflows/prism.yml']
  ].map(([id,standard,obligation,source,evidence])=>({id,standard,obligation,source,evidence,status:'Documented obligation and named evidence procedure; not an external compliance certification.'}));
  body=[structure('Obligation',{id:'String',standard:'String',obligation:'String',source:'String',evidence:'String',status:'String'})];
  compliance.forEach(r=>body.push(row('obligation'+r.id,'Obligation',r)));
  body.push(def('obligations','(List Obligation)',list('Obligation',compliance.map(r=>call('obligation'+r.id)))));
  body.push(def('scope','String',q('Standards organize and test the product model; these declarations do not assert organizational, legal, security or whole-browser certification. Evidence is qualified only by its exact observed run and stated scope.')));
  emit('Compliance','standards and evidence obligations',[],body,[...compliance.flatMap(r=>[r.source,r.evidence]).filter(p=>!outputs.has(p))],compliance.length);
  // Every generated module is inventoried by actual declaration counts, and its
  // sources are complete files. Zero/zero deliberately does not claim a span.
  for(const m of modules) {
    const text=outputs.get(m.path);
    m.records=(text.match(/\bbody: \(record /g)||[]).length;
    m.declarations=(text.match(/^(?:definition|structure|inductive|theorem)\{/gm)||[]).length;
    m.sha256=hash(text);
  }
  const moduleTexts=new Map(modules.map(m=>[m.module,outputs.get(m.path)]));
  moduleTexts.set('Product.Architecture',read('app/src/Product/Architecture.lex.tex'));
  moduleTexts.set('Product.Experience',experience);
  validateFacetReferences(moduleTexts);
  for(const s of stakeholders)if(!goals.some(g=>g.user===s.index))fail(`stakeholder has no typed goal ${s.declaration}`);
  const provenance=JSON.parse(read('product/facet-type-provenance.json'));
  for(const item of provenance.types)if(hash(read(item.path))!==item.derivedSha256)fail(`modified reference type ${item.path}`);
  read('product/UORUST-LICENSE-MIT.txt');read('scripts/check-facets.mjs');
  const catalog={format:'stitch/product-facets/1',assurance:'Source-derived product inventory and obligations, not a verification receipt or whole-product certificate.',sourceConvention:'Source firstLine=0,lastLine=0 means SHA-256 of the complete UTF-8 file bytes, not a precise source span.',references:[REF+'scripts/self-model/facets.py','https://github.com/afflom/prism-devrel/blob/7b6c54bb6e34f3b970f70d50127ab520367b84ac/scripts/experience/experience.py'],sources:[...sources].sort(([a],[b])=>a.localeCompare(b,'en')).map(([path,sha256])=>({path,sha256})),modules,operatorActionCount:actions.length,features,journeys:journeyRows,design,security,quality,brand,users,persistence,release,compliance};
  outputs.set('product/facets.json',JSON.stringify(catalog,null,2)+'\n');
  const summaries={Features:'Every live operator action and its guarded journey, linked to executable evidence.',Design:'The five-layer component graph, object process, publication sequence and unknown-write state machine.',Security:'Assets, STRIDE threats, qualitative risk assessments and traceable controls without false pass claims.',Quality:'Source-derived coverage, configured resource limits, zero-defect requirements and open observations.',Brand:'Stitch own palette, typography and scoped text-contrast measurements.',Users:'Real user groups, goals, tasks and environments; usability studies remain open.',Persistence:'What restores automatically, what remains volatile, and which trust decisions and effect outcomes require explicit handling.',Release:'Complete dependency/deployment inventory and separate source, native, runtime and browser qualification.',Compliance:'Named standards obligations, evidence procedures and explicit certification boundaries.'};
  outputs.set('site/facets.json',JSON.stringify({format:'stitch/site-facets/1',assurance:catalog.assurance,facets:modules.map(m=>({name:m.module,source:m.path,summary:summaries[m.module.split('.').at(-1)],count:m.declarations,evidenceStatus:'Source-derived inventory; exact-revision SDK and browser qualification required'}))},null,2)+'\n');
  return {outputs,catalog};
}
export function checkFacets(base=root) {
  const {outputs,catalog}=generateFacets(base);
  for(const [path,expected]of outputs){if(!existsSync(resolve(base,path)))fail(`missing output ${path}`);if(readFileSync(resolve(base,path),'utf8')!==expected)fail(`stale output ${path}; run node scripts/check-facets.mjs --write`);}
  return catalog;
}
export function writeFacets(base=root) {
  const {outputs,catalog}=generateFacets(base);
  for(const [path,text]of outputs){mkdirSync(dirname(resolve(base,path)),{recursive:true});writeFileSync(resolve(base,path),text);}
  return catalog;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const args=process.argv.slice(2);if(args.length>1||args.length&&!['--check','--write'].includes(args[0]))fail('usage: node scripts/check-facets.mjs [--check|--write]');
  const c=args[0]==='--write'?writeFacets():checkFacets();
  console.log(`Stitch facets ${args[0]==='--write'?'written':'fresh'}: ${c.modules.length} modules, ${c.features.length} features (${c.operatorActionCount} operator actions), ${c.security.length} threats. No verifier result asserted.`);
}
