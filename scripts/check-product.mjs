#!/usr/bin/env node
/** Project-owned contract register. NOT a Prism compiler, schema, receipt or certificate. */
import { readFileSync, writeFileSync, readdirSync, lstatSync } from 'node:fs';
import { resolve, dirname, relative } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const rowTypes = new Set(['Component','Assumption','CapabilityContract','Dependency','Deployment','Asset']);
const fail = message => { throw Error(`product register: ${message}`); };
function lex(source) {
  const out = []; let rest=source;
  while(rest.length) {
    const m=/^(?:\s+|"(?:[^"\\]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*"|:=|::|[(){}:,]|[0-9]+|[A-Za-z_][A-Za-z0-9_.]*)/.exec(rest);
    if(!m)fail('unsupported literal source');
    rest=rest.slice(m[0].length); if(!/^\s/.test(m[0]))out.push(m[0]);
  }
  return out;
}
class Literal {
  constructor(tokens){this.tokens=tokens;this.i=0;}
  take(want){const x=this.tokens[this.i++];if(want!==undefined&&x!==want)fail(`expected ${want}, got ${x}`);return x;}
  name(){const n=this.take();return this.tokens[this.i]==='::'?(this.take(),n+'::'+this.take()):n;}
  value(){
    const token=this.take();
    if(token?.startsWith('"'))return JSON.parse(token);
    if(token==='true'||token==='false')return token==='true';
    if(/^\d+$/.test(token??''))return Number(token);
    if(token!=='(')fail(`unsupported literal ${token}`);
    const kind=this.take();let value;
    if(kind==='nil'){this.name();value=[];}
    else if(kind==='cons'){const head=this.value(),tail=this.value();if(!Array.isArray(tail))fail('non-list tail');value=[head,...tail];}
    else if(kind==='ctor'){value={constructor:this.name()};}
    else if(kind==='record'){
      const type=this.name(),fields={};this.take('{');
      while(this.tokens[this.i]!=='}'){
        const name=this.take();this.take(':=');if(Object.hasOwn(fields,name))fail('duplicate field');fields[name]=this.value();
        if(this.tokens[this.i]!=='}')this.take(',');
      }
      this.take('}');value={type,fields};
    } else fail(`unsupported literal form ${kind}`);
    this.take(')');return value;
  }
}
export function literalRows(source, types=rowTypes) {
  const regex=/definition\{\s*name: ([A-Za-z_][A-Za-z0-9_]*),\s*parameters: \[\],\s*result: ([A-Za-z_.:]+),\s*body: /g;
  const rows=[];let m;
  while((m=regex.exec(source))){
    if(!types.has(m[2]))continue;
    const start=regex.lastIndex;let depth=0,quoted=false,escaped=false,end=start;
    for(;end<source.length;end++){
      const c=source[end];
      if(quoted){if(escaped)escaped=false;else if(c==='\\')escaped=true;else if(c==='"')quoted=false;continue;}
      if(c==='"'){quoted=true;continue;}if(c==='(')depth++;if(c===')'&&!--depth){end++;break;}
    }
    const parser=new Literal(lex(source.slice(start,end)));const value=parser.value();
    if(parser.i!==parser.tokens.length||value.type!==m[2])fail('noncanonical literal row');
    rows.push({declaration:m[1],type:m[2],...value.fields});regex.lastIndex=end;
  }
  return rows;
}
function walk(directory){
  if(!lstatSync(directory).isDirectory())fail(`not a nonsymlink resource directory ${directory}`);
  return readdirSync(directory).sort().flatMap(name=>{
    const path=resolve(directory,name),stat=lstatSync(path);
    if(stat.isSymbolicLink())fail(`resource symlink ${path}`);
    if(stat.isDirectory())return walk(path);
    if(!stat.isFile())fail(`not a regular resource ${path}`);
    return [path];
  });
}
function bytes(path,base=root){
  if(!/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(path)||path.split('/').some(x=>x==='.'||x==='..'))fail(`unsafe path ${path}`);
  if(!lstatSync(base).isDirectory())fail('base is not a nonsymlink directory');
  const parts=path.split('/');
  for(let i=1;i<parts.length;i++)if(!lstatSync(resolve(base,...parts.slice(0,i))).isDirectory())fail(`artifact parent is not a nonsymlink directory ${path}`);
  const full=resolve(base,path),stat=lstatSync(full);if(!stat.isFile()||stat.isSymbolicLink())fail(`not a regular artifact ${path}`);return readFileSync(full);
}
const unique=(rows,key,label)=>{const ids=rows.map(x=>x[key]);if(ids.some(x=>typeof x!=='string'||!x)||new Set(ids).size!==ids.length)fail(`duplicate or empty ${label}`);return new Set(ids);};
export function readProduct(base=root){
  const source=readFileSync(resolve(base,'app/src/Product/Model.lex.tex'),'utf8');
  const rows=literalRows(source),typed=type=>rows.filter(r=>r.type===type);
  const architecture=literalRows(readFileSync(resolve(base,'app/src/Product/Architecture.lex.tex'),'utf8'),new Set(['Foundation.Arch::Component','Foundation.Arch::Edge','Foundation.Arch::Stakeholder','Foundation.Arch::Concern','Foundation.Arch::Viewpoint','Foundation.Arch::View']));
  const hostSource=readFileSync(resolve(base,'app/src/Product/Host.lex.tex'),'utf8');
  const capabilityBlock=/name: Capability,[\s\S]*?constructors: \[([\s\S]*?)\n  \]\s*\}/.exec(hostSource)?.[1]??fail('missing Host.Capability');
  return {components:typed('Component'),assumptions:typed('Assumption'),capabilities:typed('CapabilityContract'),dependencies:typed('Dependency'),deployments:typed('Deployment'),assets:typed('Asset'),architecture,hostCapabilities:[...capabilityBlock.matchAll(/name: (\w+), fields: \[\]/g)].map(m=>m[1])};
}
export function validateProduct(p,base=root){
  const components=unique(p.components,'id','component'),assumptions=unique(p.assumptions,'id','assumption'),caps=unique(p.capabilities,'id','capability'),assets=unique(p.assets,'path','asset');
  unique(p.dependencies,'id','dependency');unique(p.deployments,'id','deployment');
  const host=new Set(p.hostCapabilities);
  if(host.size!==p.capabilities.length||new Set(p.capabilities.map(c=>c.capability)).size!==host.size)fail('host capability coverage');
  const modelModules=new Set(walk(resolve(base,'app/src')).filter(x=>x.endsWith('.lex.tex')).map(x=>/^\\begin\{lexlean\}\{([^}]+)\}/.exec(readFileSync(x,'utf8'))?.[1]));
  for(const c of p.components){
    for(const path of c.implementation){if(!assets.has(path))fail(`unregistered component asset ${path}`);bytes(path,base);}
    for(const model of c.models)if(!modelModules.has(model))fail(`unknown model ${model}`);
  }
  for(const c of p.capabilities){
    if(!components.has(c.owner))fail(`unknown capability owner ${c.owner}`);
    if(!host.has(c.capability))fail(`unknown host capability ${c.capability}`);
    for(const a of c.assumptions)if(!assumptions.has(a))fail(`unknown assumption ${a}`);
    if(!c.preconditions.length||!c.failures.length||!c.proofScope)fail(`incomplete capability ${c.id}`);
    bytes(c.source,base);
  }
  for(const d of p.dependencies)if(!components.has(d.consumer))fail(`unknown dependency consumer ${d.consumer}`);
  for(const d of p.deployments){bytes(d.entry,base);for(const cap of d.requiredCapabilities)if(!caps.has(cap))fail(`unknown deployment capability ${cap}`);}
  for(const asset of p.assets)bytes(asset.path,base);
  const runtime=['index.html',...walk(resolve(base,'src')).filter(x=>x.endsWith('.js')).map(x=>relative(base,x)),...walk(resolve(base,'v86')).map(x=>relative(base,x)),...walk(resolve(base,'images')).map(x=>relative(base,x)),...walk(resolve(base,'site')).map(x=>relative(base,x))];
  for(const path of runtime)if(!assets.has(path))fail(`unmodeled browser artifact ${path}`);
  const arch=p.architecture.filter(x=>x.type==='Foundation.Arch::Component');
  if(arch.length!==components.size||new Set(arch.map(x=>x.name)).size!==components.size||arch.some(x=>!components.has(x.name)))fail('architecture component coverage');
  for(const type of new Set(p.architecture.map(x=>x.type))){
    const rows=p.architecture.filter(x=>x.type===type).sort((a,b)=>a.declaration.localeCompare(b.declaration,'en'));
    rows.forEach((row,i)=>{if(row.index!==i)fail(`noncanonical architecture index ${row.declaration}`);});
  }
  for(const e of p.architecture.filter(x=>x.type==='Foundation.Arch::Edge'))if(!arch.some(x=>x.index===e.fromIndex)||!arch.some(x=>x.index===e.toIndex))fail('dangling architecture edge');
  const native=p.capabilities.find(x=>x.capability==='NativeRouting');if(!native||native.enabledByDefault||!native.proofScope.startsWith('Unsupported'))fail('native routing overclaim');
  const relay=p.capabilities.find(x=>x.capability==='PublicRelay');if(!relay||relay.enabledByDefault||!relay.assumptions.includes('disclosureConsent'))fail('relay consent boundary');
  const distribution=JSON.parse(bytes('vendor/distribution.json',base));
  for(const asset of p.assets.filter(a=>a.redistributionCleared && /^(v86|images)\//.test(a.path))){
    const evidence=distribution.assets[asset.path];
    if(!evidence || hash(bytes(asset.path,base))!==evidence.sha256)fail(`distribution identity mismatch ${asset.path}`);
    if(!evidence.materials?.length)fail(`missing distribution materials ${asset.path}`);
    for(const material of evidence.materials)if(hash(bytes(material.path,base))!==material.sha256)fail(`distribution material mismatch ${material.path}`);
  }
  return true;
}
/** Project resources are byte inventory, never fabricated proof evidence. */
export function resourceInventory(base=root){
  const directories=['product','docs','scripts','tests','.github/workflows'];
  const required=['product/facets.json','product/facet-type-provenance.json','site/facets.json'];
  const discovered=[...walk(resolve(base,'app/src')).filter(x=>x.endsWith('.lex.tex')),
    ...walk(resolve(base,'app/language')),
    ...directories.flatMap(path=>walk(resolve(base,path)))].map(path=>relative(base,path));
  const sourcePaths=[...new Set([...required,...discovered,
    'app/lexlean.lock','app/lexlean.toml','app/prismpm.toml','app/prism.toml',
    'app/lakefile.toml','app/lake-manifest.json','app/lean-toolchain',
    'README.md','.gitignore','CONTRACT.json','Cargo.toml','Cargo.lock',
    'package.json','package-lock.json','prismpm.lock','standards.lock','vendor/distribution.json'
  ])].filter(path=>path!=='product/contracts.json').sort();
  return sourcePaths.map(path=>({path,sha256:hash(bytes(path,base))}));
}
export function validateFacetBindings(base=root){
  const catalog=JSON.parse(bytes('product/facets.json',base));
  if(catalog.format!=='stitch/product-facets/1'||!Array.isArray(catalog.sources)||!catalog.sources.length||!Array.isArray(catalog.modules)||!catalog.modules.length)fail('missing complete facet catalog');
  unique(catalog.sources,'path','facet source');unique(catalog.modules,'module','facet module');
  for(const source of catalog.sources)if(hash(bytes(source.path,base))!==source.sha256)fail(`stale facet source ${source.path}`);
  for(const entry of catalog.modules){
    if(!/^Product\.[A-Za-z0-9_.]+$/.test(entry.module)||entry.path!==`app/src/${entry.module.replaceAll('.','/')}.lex.tex`)fail('facet module path differs');
    if(hash(bytes(entry.path,base))!==entry.sha256)fail(`stale facet module ${entry.path}`);
    if(!bytes(entry.path,base).toString('utf8').startsWith(`\\begin{lexlean}{${entry.module}}`))fail(`facet module identity differs ${entry.path}`);
  }
  return catalog;
}
export function productRegister(base=root){
  const p=readProduct(base);validateProduct(p,base);validateFacetBindings(base);
  const sources=resourceInventory(base);
  const artifacts=p.assets.map(a=>{const data=bytes(a.path,base);return {...a,bytes:data.length,sha256:hash(data)};}).sort((a,b)=>a.path.localeCompare(b.path,'en'));
  return {format:'Stitch project-owned product contract register',version:1,assurance:'Source contracts and local byte inventory, not a Prism receipt or whole-browser proof',reference:{repository:'https://github.com/UOR-Foundation/PrismPM',revision:'fe5b8b73a94134c316329a8d1b09ebc97b555c5f',specSections:['2','11'],scope:'Product-contract convention reference; expanded types have separate exact provenance',facetTypeProvenance:'product/facet-type-provenance.json',foundationArch:'Type-only declarations and pinned UORust design-view extensions; source identities and derivation scope are recorded in facet-type-provenance.json; no proof admission implied',sdk:'Existing prismpm.lock; no dependency or profile upgrade'},releaseBlockers:artifacts.filter(a=>!a.redistributionCleared).map(a=>({path:a.path,reason:a.licenseStatus})),...p,assets:artifacts,sources,sourceDigest:'sha256:'+hash(JSON.stringify(sources))};
}
export function run(args=process.argv.slice(2)){
  if(args.length>1||args.length===1&&!['--write','--check'].includes(args[0]))fail('usage: node scripts/check-product.mjs [--write|--check]');
  const output=resolve(root,'product/contracts.json'),expected=JSON.stringify(productRegister(),null,2)+'\n';
  if(args[0]==='--write'){writeFileSync(output,expected);process.stdout.write('Wrote project-owned product register; no verification claim.\n');}
  else {if(readFileSync(output,'utf8')!==expected)fail('stale product/contracts.json; run node scripts/check-product.mjs --write');process.stdout.write('Product graph, architecture, source binding and local artifact inventory match.\n');}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))run();
