import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { encodeExample, inspectExample, hexPreview, EXPLORER_BYTE_LIMIT } from '../site/explorer.js';

test('local explorer uses real exact commitments and recovers every valid fragment pair', async () => {
  for (const text of ['', 'a', 'Stitch', 'Exact bytes 🧵', 'e\u0301', '<script>not HTML</script>']) {
    const object = await encodeExample(text);
    assert.match(object.manifest.object.contentDigest, /^sha256:[a-f0-9]{64}$/);
    for (const mask of [[true,true,true], [true,true,false], [true,false,true], [false,true,true]]) {
      const result = await inspectExample(object, mask);
      assert.equal(result.state, 'recovered');
      assert.deepEqual(result.bytes, new TextEncoder().encode(text));
    }
  }
});

test('missing information and tampering never become accepted output', async () => {
  const object = await encodeExample('A small recoverable object');
  for (const mask of [[false,false,false], [true,false,false], [false,true,false], [false,false,true]]) {
    const result = await inspectExample(object, mask); assert.equal(result.state, 'insufficient'); assert.equal(result.bytes, null);
  }
  for (const corrupt of [0, 1, 2]) {
    const result = await inspectExample(object, [true,true,true], corrupt);
    assert.equal(result.state, 'refused'); assert.match(result.detail, /FragmentDigestMismatch/); assert.equal(result.bytes, null);
    const mask = [true,true,true]; mask[corrupt] = false;
    assert.equal((await inspectExample(object, mask, corrupt)).state, 'recovered');
  }
  assert.equal((await inspectExample(object)).state, 'recovered', 'tamper tests must not modify original bytes');
});

test('explorer has a real byte ceiling and bounded hex preview', async () => {
  await encodeExample('x'.repeat(EXPLORER_BYTE_LIMIT));
  await assert.rejects(encodeExample('x'.repeat(EXPLORER_BYTE_LIMIT + 1)), /256 UTF-8 bytes/);
  await assert.rejects(encodeExample('🧵'.repeat(65)), /256 UTF-8 bytes/);
  await assert.rejects(encodeExample(null), TypeError);
  assert.equal(hexPreview(new Uint8Array()), '(empty)');
  assert.equal(hexPreview(new Uint8Array([0, 15, 255])), '00 0f ff');
  assert.match(hexPreview(new Uint8Array(17)), / …$/);
  await assert.rejects(inspectExample(await encodeExample('a'), [true]), TypeError);
});

test('reader surface retains console controls and keeps hash navigation and transport out of the local explorer', () => {
  const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
  const script = readFileSync(new URL('../site/explorer.js', import.meta.url), 'utf8');
  const svg = readFileSync(new URL('../site/stitch-fabric.svg', import.meta.url), 'utf8');
  for (const id of ['protocolExplorer','protocolMap','operatorConsole','operatorJourneyNav','allowMeshSignalingInput','allowPublicRelayInput','productTitle']) assert.ok(html.includes(`id="${id}"`), id);
  assert.doesNotMatch(script, /fetch\(|WebSocket|RTCPeerConnection|localStorage|innerHTML|location\.hash\s*=/);
  assert.doesNotMatch(html, /href="#/);
  assert.match(script, /from '\.\.\/src\/layer3-storage\/custody\.js'/);
  assert.match(svg, /viewBox="0 0 960 720"/);
  assert.match(svg, /<title/); assert.match(svg, /<desc/);
  assert.equal((html.match(/<h1\b/g) || []).length, 1);
});

test('facet inventory accepts only bounded source records and never treats metadata as executable markup', async () => {
  const { validateCatalog } = await import('../site/catalog.js');
  const catalog = { format: 'stitch/site-facets/1', assurance: 'Source inventory, not proof.', facets: [{ name: 'Features', source: 'app/src/Product/Features.lex.tex', summary: 'Features and their relationships.', count: 4, evidenceStatus: 'Source-derived inventory' }] };
  assert.equal(validateCatalog(catalog), catalog);
  for (const source of ['javascript:alert(1)', '../secrets', 'app/src/../../bad.lex.tex', 'https://example.com']) {
    assert.throws(() => validateCatalog({ ...catalog, facets: [{ ...catalog.facets[0], source }] }), TypeError);
  }
  assert.throws(() => validateCatalog({ ...catalog, facets: [...catalog.facets, ...catalog.facets] }), TypeError);
  const script = readFileSync(new URL('../site/catalog.js', import.meta.url), 'utf8');
  assert.doesNotMatch(script, /innerHTML|eval\(/);
});

function exampleDocument() {
  const elements = new Map();
  const getElementById = id => {
    if (!elements.has(id)) elements.set(id, { value: '', textContent: '', hidden: false, disabled: false, checked: true, dataset: {}, attributes: {}, listeners: {},
      setAttribute(key, value) { this.attributes[key] = value; },
      addEventListener(event, callback) { this.listeners[event] = callback; },
    });
    return elements.get(id);
  };
  return { getElementById };
}
const tick = () => new Promise(resolve => setTimeout(resolve, 5));
async function until(predicate) {
  for (let i = 0; i < 200; i++) { if (predicate()) return; await tick(); }
  assert.fail('Timed out waiting for local explorer state');
}

test('encoding interruptions gate old controls, preserve newest result and clear busy state', async () => {
  const { installExplorer } = await import('../site/explorer.js');
  const document = exampleDocument(), get = document.getElementById;
  let release;
  const held = new Promise(resolve => { release = resolve; });
  const explorer = installExplorer(document, { encodeObject: async text => {
    if (text === 'old in-flight input') await held;
    return encodeExample(text);
  } });
  await until(() => get('exampleResult').dataset.state === 'recovered');
  get('exampleInput').value = 'old in-flight input';
  const old = explorer.encode();
  assert.equal(get('encodeExample').disabled, true);
  assert.equal(get('exampleControls').hidden, true);
  get('presettamper').listeners.click();
  get('available0').checked = false; get('available0').listeners.change();
  get('exampleInput').value = 'new exact input';
  await explorer.encode();
  assert.equal(get('recoveredText').textContent, 'new exact input');
  assert.equal(get('encodeExample').disabled, false);
  release(); await old;
  assert.equal(get('recoveredText').textContent, 'new exact input');
  assert.equal(get('exampleControls').hidden, false);
  assert.doesNotMatch(get('exampleInputStatus').textContent, /Encoding/);
  get('exampleInput').value = '🧵'.repeat(65); await explorer.encode();
  assert.equal(get('exampleControls').hidden, true);
  assert.match(get('exampleInputStatus').textContent, /256 UTF-8 bytes/);
  assert.equal(get('encodeExample').disabled, false);
});

test('late inspections cannot overwrite the most recent fragment scenario', async () => {
  const { installExplorer } = await import('../site/explorer.js');
  const document = exampleDocument(), get = document.getElementById;
  let release, holdNext = false;
  const held = new Promise(resolve => { release = resolve; });
  installExplorer(document, { inspectObject: async (...args) => {
    if (holdNext) { holdNext = false; await held; }
    return inspectExample(...args);
  } });
  await until(() => get('exampleResult').dataset.state === 'recovered');
  holdNext = true; get('presettamper').listeners.click();
  get('presetone').listeners.click();
  await until(() => get('exampleResult').dataset.state === 'recovered');
  release(); await tick(); await tick();
  assert.equal(get('exampleResult').dataset.state, 'recovered');
  assert.equal(get('recoveryCount').textContent, '2 / 3');
});
