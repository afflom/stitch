import test from 'node:test';
import assert from 'node:assert/strict';
import {cpSync,mkdirSync,mkdtempSync,readFileSync,rmSync,symlinkSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {resourceInventory,validateFacetBindings,readProduct,validateProduct} from '../scripts/check-product.mjs';
const root=resolve(import.meta.dirname,'..');
function resources(t){
  const base=mkdtempSync(join(tmpdir(),'stitch-resource-inventory-'));t.after(()=>rmSync(base,{recursive:true,force:true}));
  const paths=new Set(resourceInventory(root).map(x=>x.path));
  const catalog=JSON.parse(readFileSync(join(root,'product/facets.json')));
  for(const row of catalog.sources)paths.add(row.path);
  for(const path of paths){mkdirSync(dirname(join(base,path)),{recursive:true});cpSync(join(root,path),join(base,path));}
  return base;
}
test('resource inventory covers source, provenance, evidence and the authoring controls without self-binding',()=>{
  const rows=resourceInventory(root),paths=new Set(rows.map(x=>x.path));
  for(const path of ['product/facets.json','product/facet-type-provenance.json','product/source-verification.json','product/source-attestation.json','product/source-build-manifest.json','product/UORUST-LICENSE-MIT.txt','docs/complete-prism.md','docs/reader-experience.md','scripts/author-source.sh','scripts/retain-authoring-evidence.mjs','.github/workflows/source-authoring.yml','tests/product-inventory.test.js','app/lexlean.lock','site/facets.json'])assert.ok(paths.has(path),path);
  assert.ok(!paths.has('product/contracts.json'));assert.equal(paths.size,rows.length);
  assert.deepEqual(rows.map(x=>x.path),[...paths].sort());
});
test('new resources and changed retained evidence change the inventory, not proof status',t=>{
  const base=resources(t),before=resourceInventory(base);
  writeFileSync(join(base,'docs/new-review.md'),'New review input.');assert.ok(resourceInventory(base).some(x=>x.path==='docs/new-review.md'));
  const path='product/source-verification.json';writeFileSync(join(base,path),readFileSync(join(base,path),'utf8')+'\n');
  assert.notEqual(resourceInventory(base).find(x=>x.path===path).sha256,before.find(x=>x.path===path).sha256);
});
test('required facet resources cannot disappear from a freshly written register',t=>{
  const base=resources(t);rmSync(join(base,'product/facets.json'));assert.throws(()=>resourceInventory(base),/ENOENT/);
});
test('resource symlinks and parent aliases refuse instead of hiding alternate input bytes',t=>{
  const base=resources(t);symlinkSync(join(root,'README.md'),join(base,'docs/linked.md'));assert.throws(()=>resourceInventory(base),/resource symlink/);
  rmSync(join(base,'docs/linked.md'));rmSync(join(base,'docs'),{recursive:true});symlinkSync(join(root,'docs'),join(base,'docs'));assert.throws(()=>resourceInventory(base),/nonsymlink resource directory/);
});
test('changed facet inputs and missing generated module fail before register regeneration',t=>{
  const base=resources(t);validateFacetBindings(base);
  writeFileSync(join(base,'index.html'),readFileSync(join(base,'index.html'),'utf8')+'\n');assert.throws(()=>validateFacetBindings(base),/stale facet source index.html/);
  cpSync(join(root,'index.html'),join(base,'index.html'));
  const first=JSON.parse(readFileSync(join(base,'product/facets.json'))).modules[0];rmSync(join(base,first.path));assert.throws(()=>validateFacetBindings(base),/ENOENT/);
});
test('every shipped site file is source-declared and omitting its record refuses',()=>{
  const p=readProduct(root);
  for(const path of ['site/site.css','site/explorer.js','site/catalog.js','site/stitch-fabric.svg','site/facets.json']){
    assert.ok(p.assets.some(a=>a.path===path));assert.ok(p.components.find(c=>c.id==='browser').implementation.includes(path));
    const changed=structuredClone(p);changed.assets=changed.assets.filter(a=>a.path!==path);assert.throws(()=>validateProduct(changed,root),/unregistered component asset|unmodeled browser artifact/);
  }
});
