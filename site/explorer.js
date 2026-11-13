/** Local teaching surface. Reuses Stitch's real byte/manifest verifier, never transport. */
import { createObject, recoverObject } from '../src/layer3-storage/custody.js';

export const EXPLORER_BYTE_LIMIT = 256;
export const DEFAULT_MESSAGE = 'Keep the bytes. Change the peers.';
export const FRAGMENT_NAMES = Object.freeze(['A', 'B', 'Parity']);

export async function encodeExample(text) {
  if (typeof text !== 'string') throw new TypeError('Enter text to encode.');
  const bytes = new TextEncoder().encode(text);
  if (bytes.length > EXPLORER_BYTE_LIMIT) throw new RangeError('Use at most 256 UTF-8 bytes in this local example.');
  return { text, bytes, ...await createObject(bytes) };
}

export async function inspectExample(example, available = [true, true, true], corrupted = null) {
  if (!Array.isArray(available) || available.length !== 3 || available.some(x => typeof x !== 'boolean')) throw new TypeError('Choose the three fragment availability states.');
  if (corrupted !== null && ![0, 1, 2].includes(corrupted)) throw new TypeError('Choose a valid fragment to alter.');
  const supplied = example.fragments.filter(f => available[f.index]).map(f => ({ index: f.index, bytes: new Uint8Array(f.bytes) }));
  const altered = supplied.find(f => f.index === corrupted);
  if (altered && altered.bytes.length) altered.bytes[0] ^= 1;
  if (supplied.length < 2) return { state: 'insufficient', count: supplied.length, title: 'Not enough fragments.', detail: 'Two distinct compatible fragments are required. The missing information cannot be recreated from one.', bytes: null };
  try {
    const bytes = await recoverObject(example.manifest, supplied);
    return { state: 'recovered', count: supplied.length, title: 'Exact bytes recovered.', detail: 'The supplied fragment commitments, encoding and reconstructed object all passed the existing Stitch verifier.', bytes };
  } catch (error) {
    return { state: 'refused', count: supplied.length, title: 'Changed bytes refused.', detail: `Verification stopped (${error.code || 'verification error'}). Every supplied fragment is checked, even when two other fragments are intact.`, bytes: null };
  }
}

export function hexPreview(bytes) {
  return [...bytes.slice(0, 16)].map(b => b.toString(16).padStart(2, '0')).join(' ') + (bytes.length > 16 ? ' …' : '') || '(empty)';
}

export function installExplorer(document, { encodeObject = encodeExample, inspectObject = inspectExample } = {}) {
  const get = id => document.getElementById(id);
  let example = null;
  let generation = 0;
  let encodeEpoch = 0;
  let encoding = false;
  let available = [true, true, true];
  let corrupted = null;
  const form = get('exampleForm');
  function resetControls() {
    available = [true, true, true]; corrupted = null;
  }
  function renderFragments() {
    example.fragments.forEach(fragment => {
      const index = fragment.index;
      const bytes = new Uint8Array(fragment.bytes);
      if (corrupted === index && bytes.length) bytes[0] ^= 1;
      get(`fragment${index}`).dataset.available = String(available[index]);
      get(`fragment${index}`).dataset.corrupted = String(corrupted === index);
      get(`available${index}`).checked = available[index];
      get(`fragmentBytes${index}`).textContent = hexPreview(bytes);
      get(`fragmentSize${index}`).textContent = `${fragment.bytes.length} bytes`;
      get(`fragmentState${index}`).textContent = !available[index] ? 'WITHHELD FROM RECOVERY' : corrupted === index ? 'ONE BYTE CHANGED' : 'SUPPLIED UNCHANGED';
      get(`corrupt${index}`).disabled = !available[index] || !bytes.length;
      get(`corrupt${index}`).textContent = corrupted === index ? 'Restore byte' : 'Change one byte';
      get(`corrupt${index}`).setAttribute('aria-pressed', String(corrupted === index));
    });
  }
  async function inspect() {
    if (!example || encoding) return;
    const version = ++generation;
    renderFragments();
    const result = get('exampleResult');
    result.dataset.state = 'checking';
    get('exampleResultTitle').textContent = 'Checking exact commitments…';
    get('exampleResultDetail').textContent = 'Local verification is running.';
    get('recoveredText').textContent = '';
    get('recoveryCount').textContent = `${available.filter(Boolean).length} / 3`;
    try {
      const observation = await inspectObject(example, [...available], corrupted);
      if (version !== generation) return;
      result.dataset.state = observation.state;
      get('exampleResultTitle').textContent = observation.title;
      get('exampleResultDetail').textContent = observation.detail;
      get('recoveredText').textContent = observation.bytes === null ? 'No recovered output accepted.' : new TextDecoder().decode(observation.bytes) || '(empty object)';
    } catch (error) {
      if (version !== generation) return;
      result.dataset.state = 'refused';
      get('exampleResultTitle').textContent = 'Local verification unavailable.';
      get('exampleResultDetail').textContent = error.message;
    }
  }
  async function encode() {
    const epoch = ++encodeEpoch;
    ++generation; // Pending inspections of the previous sample cannot publish.
    encoding = true;
    get('encodeExample').disabled = true;
    get('exampleControls').hidden = true; // No old result may describe the edited input.
    get('exampleInputStatus').textContent = 'Encoding and committing the input locally…';
    try {
      const next = await encodeObject(get('exampleInput').value);
      if (epoch !== encodeEpoch) return;
      example = next; resetControls();
      get('exampleInputStatus').textContent = `${next.bytes.length} UTF-8 bytes · 3 fragments of ${next.fragments[0].bytes.length} bytes · local example only`;
      get('exampleCommitment').textContent = next.manifest.object.contentDigest;
      get('exampleControls').hidden = false;
      encoding = false;
      await inspect();
    } catch (error) {
      if (epoch !== encodeEpoch) return;
      get('exampleInputStatus').textContent = `${error.message} Encode a valid input to show a result.`;
      get('exampleControls').hidden = true;
    } finally {
      if (epoch === encodeEpoch) { encoding = false; get('encodeExample').disabled = false; }
    }
  }
  form.addEventListener('submit', event => { event.preventDefault(); void encode(); });
  [0, 1, 2].forEach(index => {
    get(`available${index}`).addEventListener('change', () => { if (encoding) return; available[index] = get(`available${index}`).checked; void inspect(); });
    get(`corrupt${index}`).addEventListener('click', () => { if (encoding) return; corrupted = corrupted === index ? null : index; void inspect(); });
  });
  const presets = { complete: [true, true, true], one: [true, false, true], two: [false, false, true], tamper: [true, true, true] };
  for (const [name, mask] of Object.entries(presets)) get(`preset${name}`).addEventListener('click', () => {
    if (encoding || !example) return;
    available = [...mask]; corrupted = name === 'tamper' && example.fragments[0].bytes.length ? 0 : null; void inspect();
  });
  get('exampleInput').value = DEFAULT_MESSAGE;
  void encode();
  return { encode, inspect };
}

if (typeof document !== 'undefined') {
  installExplorer(document);
  // The fragment identifier belongs to the mesh key. Never use it for page navigation.
  for (const button of document.querySelectorAll('[data-scroll-to]')) button.addEventListener('click', () => {
    const target = document.getElementById(button.dataset.scrollTo);
    target.focus({ preventScroll: true }); target.scrollIntoView({ behavior: 'auto', block: 'start' });
  });
}
