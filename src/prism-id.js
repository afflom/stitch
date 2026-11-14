/**
 * Prism id: a login-free identity that comes into being in the browser.
 *
 * A prism is named by the kappa of its genesis record. Devices join it only
 * through an out-of-band link offer (a QR code or any other channel the user
 * already trusts). After that, linked devices keep each other in sync over the
 * substrate message bus. Every authorization decision is taken by the
 * Stitch.PrismId model in app/src/Stitch/PrismId.lex.tex.
 *
 * kappa = "sha256:" + lowercase hex SHA-256 of uor-addr canonical JSON:
 * RFC 8785 shape, strings must already be NFC, integers only, object members
 * ordered by the UTF-8 bytes of their names.
 *
 * Only P-256 ECDSA/ECDH, HKDF-SHA-256, HMAC-SHA-256, AES-256-GCM and SHA-256
 * are required, so native, mobile (Secure Enclave, Android Keystore), TPM 2.0
 * and secure-element devices can implement the same protocol. Where the
 * platform has ML-KEM-768, every key wrap is hybrid (ECDH + ML-KEM).
 * See docs/prism-id.md and docs/prism-id-threat-model.md.
 */
import { model } from './layer1-uor/generated-model.js';
import { RELAY_EVENT_BYTES, RELAY_LIFETIMES, RelayReassembler, frameRelayMessage, newRelaySession, relayChannel, snapshotRelayMessage }
  from './layer5-transport/relay-framing.js';

const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export const KIND = Object.freeze({
  device: 'prism/device/1',
  genesis: 'prism/genesis/1',
  bind: 'prism/bind/1',
  revoke: 'prism/revoke/1',
  log: 'prism/log/1',
  offer: 'prism/link-offer/1',
  request: 'prism/link-request/1',
  response: 'prism/link-response/1',
  rendezvous: 'prism/rendezvous/1',
  sync: 'prism/sync/1',
  sealed: 'prism/sealed/1',
  boundary: 'prism/boundary/1',
  action: 'prism/action/1',
  linkCode: 'prism/link-code/1',
  keyring: 'prism/keyring/1',
  recoverySecret: 'prism/recovery-secret/1',
  recoveryShare: 'prism/recovery-share/1',
  persona: 'prism/persona/1',
  personaKey: 'prism/persona-key/1',
  personaRecovery: 'prism/persona-recovery/1'
});

/** Kinds of device that take part. Every one uses the same records and primitives. */
export const DEVICE_CLASSES = Object.freeze(['browser', 'native', 'mobile', 'embedded', 'recovery']);
/** Where a device says its private keys live. Self-asserted unless an attestation verifier confirms it. */
export const KEY_PROTECTION = Object.freeze(['software', 'platform', 'secure-element', 'threshold-shares']);
/**
 * member: full device of the prism. delegate: scoped device that never holds
 * the private boundary. recovery: an offline authority whose key exists only as
 * threshold shares held by guardians; it can link and revoke, never act at a host.
 */
export const ROLES = Object.freeze(['member', 'delegate', 'recovery']);

export class PrismIdError extends Error {
  constructor(code, message) { super(message); this.name = 'PrismIdError'; this.code = code; }
}
const refuse = (code, message) => { throw new PrismIdError(code, message); };

// ---------------------------------------------------------------- canonical form

function compareBytes(left, right) {
  const n = Math.min(left.length, right.length);
  for (let i = 0; i < n; i++) if (left[i] !== right[i]) return left[i] - right[i];
  return left.length - right.length;
}

function canonicalString(text) {
  if (!text.isWellFormed()) refuse('canonical', 'string is not well-formed Unicode');
  if (text.normalize('NFC') !== text) refuse('canonical', 'string is not in NFC');
  let out = '"';
  for (const ch of text) {
    const c = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (c === 8) out += '\\b';
    else if (c === 9) out += '\\t';
    else if (c === 10) out += '\\n';
    else if (c === 12) out += '\\f';
    else if (c === 13) out += '\\r';
    else if (c < 32) out += '\\u00' + c.toString(16).padStart(2, '0');
    else out += ch;
  }
  return out + '"';
}

/** uor-addr canonical JSON text of a JSON value. Refuses anything outside the subset. */
export function canonicalJson(value) {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) refuse('canonical', 'number outside the integer subset');
    return String(value);
  }
  if (typeof value === 'string') return canonicalString(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    const members = Object.keys(value).map(key => {
      if (value[key] === undefined) refuse('canonical', `member ${key} is undefined`);
      return { key, bytes: encoder.encode(key) };
    });
    members.sort((a, b) => compareBytes(a.bytes, b.bytes));
    return '{' + members.map(m => canonicalString(m.key) + ':' + canonicalJson(value[m.key])).join(',') + '}';
  }
  return refuse('canonical', `value of type ${typeof value} is not JSON`);
}

export const canonicalBytes = value => encoder.encode(canonicalJson(value));

const hex = bytes => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');

/** kappa of a JSON value. */
export async function kappa(value) {
  return 'sha256:' + hex(await subtle.digest('SHA-256', canonicalBytes(value)));
}

export function isKappa(text) { return typeof text === 'string' && /^sha256:[0-9a-f]{64}$/.test(text); }

export function toBase64Url(bytes) {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function fromBase64Url(text) {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) refuse('encoding', 'not base64url');
  const s = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - text.length % 4) % 4));
  return Uint8Array.from(s, c => c.charCodeAt(0));
}
const random = n => globalThis.crypto.getRandomValues(new Uint8Array(n));


// ---------------------------------------------------------------- devices

const SIGN = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN_HASH = { name: 'ECDSA', hash: 'SHA-256' };
const AGREE = { name: 'ECDH', namedCurve: 'P-256' };
const KEM = { name: 'ML-KEM-768' };
const KEM_PUBLIC_BYTES = 1184;
const publicJwk = ({ kty, crv, x, y }) => ({ crv, kty, x, y });

let kemSupport;
/** Whether this platform offers ML-KEM-768 in WebCrypto. */
export async function postQuantumAvailable() {
  if (kemSupport === undefined) {
    try { await subtle.generateKey(KEM, false, ['encapsulateBits', 'decapsulateBits']); kemSupport = true; }
    catch { kemSupport = false; }
  }
  return kemSupport;
}

async function newKeys(extractable) {
  const signing = await subtle.generateKey(SIGN, extractable, ['sign', 'verify']);
  const agreement = await subtle.generateKey(AGREE, extractable, ['deriveBits']);
  const kem = await postQuantumAvailable() ? await subtle.generateKey(KEM, extractable, ['encapsulateBits', 'decapsulateBits']) : null;
  return { signing, agreement, kem };
}

async function deviceFromKeys({ signing, agreement, kem }, deviceClass, protection) {
  const record = {
    kind: KIND.device,
    class: deviceClass,
    protection,
    sign: publicJwk(await subtle.exportKey('jwk', signing.publicKey)),
    agree: publicJwk(await subtle.exportKey('jwk', agreement.publicKey))
  };
  if (kem) record.kem = toBase64Url(await subtle.exportKey('raw-public', kem.publicKey));
  return Object.freeze({ id: await kappa(record), record, signingKey: signing.privateKey, agreementKey: agreement.privateKey, kemKey: kem?.privateKey ?? null });
}

/**
 * A device holds non-extractable private keys: one signs prism records, one
 * agrees keys for wrapping, and where the platform has it an ML-KEM-768 key
 * makes every wrap to this device hybrid. Only its public record leaves the
 * device. `deviceClass` and `protection` are claims the device makes about itself.
 */
export async function createDevice({ deviceClass = 'browser', protection = 'software' } = {}) {
  if (!DEVICE_CLASSES.includes(deviceClass) || deviceClass === 'recovery') refuse('device', `unknown device class ${deviceClass}`);
  if (!KEY_PROTECTION.includes(protection) || protection === 'threshold-shares') refuse('device', `unknown key protection ${protection}`);
  return deviceFromKeys(await newKeys(false), deviceClass, protection);
}

const okKey = k => k && k.kty === 'EC' && k.crv === 'P-256' && typeof k.x === 'string' && typeof k.y === 'string' && Object.keys(k).length === 4;

export function checkDeviceRecord(record) {
  const keys = record ? Object.keys(record).length : 0;
  const kemOk = record?.kem === undefined ? keys === 5 : keys === 6 && fromBase64Url(record.kem).length === KEM_PUBLIC_BYTES;
  if (!record || record.kind !== KIND.device || !kemOk || !DEVICE_CLASSES.includes(record.class) ||
    !KEY_PROTECTION.includes(record.protection) || !okKey(record.sign) || !okKey(record.agree)) refuse('device', 'malformed device record');
  return record;
}

async function signRecord(device, body) {
  const signature = await subtle.sign(SIGN_HASH, device.signingKey, canonicalBytes(body));
  return { body, signer: device.id, signature: toBase64Url(signature) };
}

async function signatureValid(envelope, deviceRecord) {
  try {
    checkDeviceRecord(deviceRecord);
    if (await kappa(deviceRecord) !== envelope.signer) return false;
    const key = await subtle.importKey('jwk', { ...deviceRecord.sign, ext: true }, SIGN, false, ['verify']);
    return await subtle.verify(SIGN_HASH, key, fromBase64Url(envelope.signature), canonicalBytes(envelope.body));
  } catch (error) {
    if (error instanceof PrismIdError || error instanceof DOMException || error instanceof TypeError) return false;
    throw error;
  }
}

// ---------------------------------------------------------------- hybrid key wrapping

/**
 * Wrap bytes to a device record. ECDH with a fresh ephemeral key, plus
 * ML-KEM-768 encapsulation whenever the recipient advertises a KEM key. A
 * sender that cannot encapsulate refuses rather than downgrade
 * (Stitch.PrismId.hybridWrapRequired).
 */
async function wrapTo(recipient, bytes, { salt, info, aad }) {
  const ephemeral = await subtle.generateKey(AGREE, false, ['deriveBits']);
  const peer = await subtle.importKey('jwk', { ...recipient.agree, ext: true }, AGREE, false, []);
  const classical = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: peer }, ephemeral.privateKey, 256));
  let ikm = classical, kemCiphertext;
  if (recipient.kem !== undefined) {
    if (!await postQuantumAvailable()) refuse('post-quantum', 'the recipient requires a hybrid wrap and this platform has no ML-KEM');
    const kemPublic = await subtle.importKey('raw-public', fromBase64Url(recipient.kem), KEM, false, ['encapsulateBits']);
    const { sharedKey, ciphertext } = await subtle.encapsulateBits(KEM, kemPublic);
    ikm = concat(classical, new Uint8Array(sharedKey));
    kemCiphertext = toBase64Url(ciphertext);
  }
  const key = await hkdfAesKey(ikm, salt, info);
  const wrap = { agree: publicJwk(await subtle.exportKey('jwk', ephemeral.publicKey)), ...await encryptWith(key, bytes, aad) };
  if (kemCiphertext) wrap.kem = kemCiphertext;
  return wrap;
}

async function unwrapFrom(device, wrap, { salt, info, aad }) {
  if (!model['Stitch.PrismId.hybridWrapRequired'](device.record.kem !== undefined, typeof wrap.kem === 'string'))
    refuse('post-quantum', 'a wrap to a post-quantum device must be hybrid');
  const peer = await subtle.importKey('jwk', { ...wrap.agree, ext: true }, AGREE, false, []);
  let ikm = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: peer }, device.agreementKey, 256));
  if (typeof wrap.kem === 'string') {
    if (!device.kemKey) refuse('post-quantum', 'this device has no ML-KEM key');
    ikm = concat(ikm, new Uint8Array(await subtle.decapsulateBits(KEM, device.kemKey, fromBase64Url(wrap.kem))));
  }
  return decryptWith(await hkdfAesKey(ikm, salt, info), wrap, aad);
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

async function hkdfAesKey(ikm, salt, info) {
  const material = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode(info) },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function encryptWith(key, bytes, aad) {
  const iv = random(12);
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(aad) }, key, bytes);
  return { iv: toBase64Url(iv), ciphertext: toBase64Url(ciphertext) };
}
async function decryptWith(key, box, aad) {
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: fromBase64Url(box.iv), additionalData: encoder.encode(aad) }, key, fromBase64Url(box.ciphertext)));
}

// ---------------------------------------------------------------- boundary keys

/**
 * A boundary key is 32 random bytes. Sealing and topic keys are derived from
 * it with HKDF and are never extractable. The bytes themselves are kept only
 * on a sharing device (one that links members, rotates or sets up recovery);
 * a hardened device keeps the derived keys alone (Stitch.PrismId.mayShareBoundary).
 */
async function boundaryFromRaw(raw, shareable) {
  const material = await subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
  const derive = (info, algorithm, usages) => subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: encoder.encode(info) }, material, algorithm, false, usages);
  return Object.freeze({
    seal: await derive('prism/boundary-seal/1', { name: 'AES-GCM', length: 256 }, ['encrypt', 'decrypt']),
    topic: await derive('prism/boundary-topic/1', { name: 'HMAC', hash: 'SHA-256', length: 256 }, ['sign']),
    raw: shareable ? Uint8Array.from(raw) : null
  });
}

function requireShareable(session, what) {
  if (!model['Stitch.PrismId.mayShareBoundary'](session.shareable === true)) refuse('hardened', `a hardened device cannot ${what}; use a sharing member`);
}

function keyringBytes(keyring) {
  const keys = {};
  for (const [id, entry] of keyring) {
    if (!entry.raw) refuse('hardened', 'this keyring is hardened and cannot be shared');
    keys[id] = toBase64Url(entry.raw);
  }
  return canonicalBytes({ kind: KIND.keyring, keys });
}

async function keyringFromBytes(bytes, shareable) {
  const value = JSON.parse(decoder.decode(bytes));
  if (value.kind !== KIND.keyring) refuse('keyring', 'malformed keyring');
  const keyring = new Map();
  for (const [id, raw] of Object.entries(value.keys)) keyring.set(id, await boundaryFromRaw(fromBase64Url(raw), shareable));
  return keyring;
}

/**
 * Make this device hold only non-extractable boundary keys. Script running in
 * its origin can then use them while it runs but can never copy them out.
 * A hardened device can still link delegates, revoke and sync; it cannot link
 * members or set up recovery.
 */
export async function hardenSession(session) {
  const keyring = new Map();
  for (const [id, entry] of session.keyring) keyring.set(id, Object.freeze({ seal: entry.seal, topic: entry.topic, raw: null }));
  return { ...session, keyring, shareable: false };
}

// ---------------------------------------------------------------- the prism log

/** Records are kept by the kappa of their envelope, so merging is set union. */
export async function addRecord(log, envelope) {
  const next = new Map(log);
  next.set(await kappa(envelope), envelope);
  return next;
}

/** Commutative, associative and idempotent: union keyed by kappa. */
export function mergeLogs(left, right) {
  const next = new Map(left);
  for (const [k, v] of right) next.set(k, v);
  return next;
}

export async function logRoot(log) {
  return kappa({ kind: KIND.log, records: [...log.keys()].sort() });
}

/** Admission bounds for logs and sync messages from peers, checked before any parsing or signature work. */
export const MAX_LOG_RECORDS = 4096;
export const MAX_SYNC_BYTES = 4 * 1024 * 1024;

export async function logFromRecords(records) {
  if (!Array.isArray(records)) refuse('log', 'records must be an array');
  if (records.length > MAX_LOG_RECORDS) refuse('log', `log exceeds ${MAX_LOG_RECORDS} records`);
  let log = new Map();
  for (const r of records) log = await addRecord(log, r);
  return log;
}

const byKey = ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0);
const sameSet = (a, b) => a.size === b.size && [...a].every(x => b.has(x));

function bindShape(body) {
  return ROLES.includes(body.role) && Array.isArray(body.scope) && body.scope.every(x => typeof x === 'string') &&
    (body.role === 'delegate' ? body.scope.length > 0 : body.scope.length === 0);
}

/**
 * Resolve which devices may act for the prism, with what role and scope, and
 * which boundary key is current.
 *
 * - A bind counts only when Stitch.PrismId.bindAllowed holds: the signer is a
 *   linked member or recovery device (not a delegate), its signature verifies,
 *   it names this prism, and the signer is not revoked unless a revocation kept
 *   that bind. A recovery-role bind also needs Stitch.PrismId.recoveryBindAllowed:
 *   while a recovery device exists, only a recovery device may add another.
 * - Revocation wins over a concurrent bind: binds a revoked device made that
 *   the revoker did not list in `keep` are dropped.
 * - Stitch.PrismId.revocationCounts: revocations by the recovery device come
 *   first; a device the recovery device revoked has no revocations that count;
 *   only a recovery device may revoke a recovery device. So a thief holding a
 *   member device cannot lock the person out: recovery revokes the thief and
 *   the thief's revocations stop counting.
 * - Every rotating revocation carries a new boundary key (`epoch`, `wraps`).
 *   The current key is the one with the highest epoch; ties go to the smaller kappa.
 */
export async function resolvePrism(prism, log) {
  const entries = [...log.entries()].sort(byKey);
  // Every genesis of this prism has the same body (its kappa is the prism);
  // envelopes differ only by signature encoding (ECDSA signatures are
  // malleable), so any one that verifies is the genesis. A copy with a bad
  // signature cannot make the log unresolvable.
  let genesis = null;
  for (const [, e] of entries) {
    if (e?.body?.kind === KIND.genesis && await kappa(e.body) === prism && await signatureValid(e, e.body.device)) { genesis = e; break; }
  }
  if (!genesis) refuse('genesis', 'the log holds no genesis of this prism that verifies');

  const devices = new Map([[genesis.signer, genesis.body.device]]);
  const binds = [], revokes = [];
  for (const [id, e] of entries) {
    const body = e?.body;
    if (body?.prism !== prism) continue;
    if (body.kind === KIND.bind && bindShape(body)) {
      try { const r = checkDeviceRecord(body.device); const target = await kappa(r); devices.set(target, r); binds.push({ id, e, target }); }
      catch (error) { if (!(error instanceof PrismIdError)) throw error; }
    } else if (body.kind === KIND.revoke && typeof body.device === 'string' && Array.isArray(body.keep) &&
      Number.isSafeInteger(body.epoch) && body.epoch > 0 && Array.isArray(body.wraps)) revokes.push({ id, e });
  }
  const verified = new Map();
  const verify = async (id, e) => {
    if (!verified.has(id)) verified.set(id, devices.has(e.signer) && await signatureValid(e, devices.get(e.signer)));
    return verified.get(id);
  };

  let linked = new Set([genesis.signer]), roles = new Map([[genesis.signer, 'member']]), revocations = new Map();
  for (let round = 0; round <= 2 * log.size + 2; round++) {
    // Revocations by the recovery device first: they decide whose revocations count.
    const revokedByRecovery = new Set();
    for (const { id, e } of revokes) {
      if (roles.get(e.signer) === 'recovery' && linked.has(e.signer) && await verify(id, e)) revokedByRecovery.add(e.body.device);
    }
    const nextRevocations = new Map();
    for (const { id, e } of revokes) {
      const signerRole = roles.get(e.signer);
      if (!model['Stitch.PrismId.mayAdminister'](linked.has(e.signer), false, signerRole !== 'member' && signerRole !== 'recovery')) continue;
      if (!model['Stitch.PrismId.revocationCounts'](signerRole === 'recovery', revokedByRecovery.has(e.signer) && signerRole !== 'recovery',
        roles.get(e.body.device) === 'recovery')) continue;
      if (!await verify(id, e)) continue;
      const entry = nextRevocations.get(e.body.device) ?? { keep: new Set(), recoveryKeep: null, by: [] };
      for (const k of e.body.keep) entry.keep.add(k);
      if (signerRole === 'recovery') { entry.recoveryKeep ??= new Set(); for (const k of e.body.keep) entry.recoveryKeep.add(k); }
      entry.by.push({ id, e });
      nextRevocations.set(e.body.device, entry);
    }
    const nextLinked = new Set([genesis.signer]), nextRoles = new Map([[genesis.signer, 'member']]), scopes = new Map();
    for (let grew = true; grew;) {
      grew = false;
      for (const { id, e, target } of binds) {
        const current = nextRoles.get(target);
        if (current === 'member' || current === 'recovery' || (current === 'delegate' && e.body.role === 'delegate')) continue;
        // A member's revocation (with a keep list it chose) never drops a recovery bind; only recovery can.
        const revocation = nextRevocations.get(e.signer);
        const keep = e.body.role === 'recovery' ? revocation?.recoveryKeep : revocation?.keep;
        const signerRevoked = e.body.role === 'recovery' ? !!keep && !keep.has(id) : revocation !== undefined && !keep.has(id);
        const signerRole = nextRoles.get(e.signer);
        let allowed = model['Stitch.PrismId.bindAllowed'](nextLinked.has(e.signer), signerRevoked,
          signerRole !== 'member' && signerRole !== 'recovery', await verify(id, e), true);
        if (allowed && e.body.role === 'recovery') {
          const recoveryExists = [...nextRoles].some(([d, r]) => r === 'recovery' && d !== target && !nextRevocations.has(d));
          allowed = model['Stitch.PrismId.recoveryBindAllowed'](signerRole === 'recovery', recoveryExists);
        }
        if (allowed) {
          nextLinked.add(target); nextRoles.set(target, e.body.role);
          if (e.body.role === 'delegate') scopes.set(target, [...e.body.scope].sort()); else scopes.delete(target);
          grew = true;
        }
      }
    }
    const settled = sameSet(nextLinked, linked) && sameSet(new Set(nextRevocations.keys()), new Set(revocations.keys())) &&
      [...nextRoles].every(([d, r]) => roles.get(d) === r) && nextRoles.size === roles.size;
    linked = nextLinked; roles = nextRoles; revocations = nextRevocations;
    if (settled) {
      const active = [...linked].filter(d => model['Stitch.PrismId.deviceMaySign'](true, revocations.has(d))).sort();
      const rekeys = [...revocations.values()].flatMap(r => r.by).filter(r => r.e.body.wraps.length > 0)
        .sort((a, b) => b.e.body.epoch - a.e.body.epoch || (a.id < b.id ? -1 : 1));
      const boundary = rekeys.length ? { epoch: rekeys[0].e.body.epoch, keyId: rekeys[0].id } : { epoch: 0, keyId: prism };
      const maxEpoch = Math.max(0, ...[...revocations.values()].flatMap(r => r.by.map(b => b.e.body.epoch)));
      return Object.freeze({
        prism,
        active,
        revoked: [...revocations.keys()].sort(),
        roles: Object.freeze(Object.fromEntries(active.map(d => [d, roles.get(d)]))),
        scopes: Object.freeze(Object.fromEntries(active.filter(d => roles.get(d) === 'delegate').map(d => [d, scopes.get(d)]))),
        devices: Object.freeze(Object.fromEntries(active.map(d => [d, devices.get(d)]))),
        recovery: active.find(d => roles.get(d) === 'recovery') ?? null,
        boundary: Object.freeze(boundary),
        epoch: maxEpoch,
        rekeys: rekeys.map(r => ({ keyId: r.id, epoch: r.e.body.epoch, wraps: r.e.body.wraps }))
      });
    }
  }
  return refuse('resolve', 'device linkage did not settle');
}

export async function canSign(prism, log, deviceId) {
  const state = await resolvePrism(prism, log);
  return model['Stitch.PrismId.deviceMaySign'](state.active.includes(deviceId) || state.revoked.includes(deviceId), state.revoked.includes(deviceId));
}

async function mayAdminister(session) {
  const state = await resolvePrism(session.prism, session.log);
  const id = session.device.id;
  const role = state.roles[id];
  if (!model['Stitch.PrismId.mayAdminister'](state.active.includes(id), state.revoked.includes(id), role !== 'member' && role !== 'recovery'))
    refuse('unauthorized', 'this device may not administer the prism');
  return state;
}

const boundaryRecipient = role => role === 'member' || role === 'recovery';
const rekeyContext = (prism, id, epoch) => ({ salt: encoder.encode(prism), info: `prism/rekey-wrap/1 ${id}`, aad: `${prism} ${epoch}` });

/** Take up any boundary keys wrapped to this device by revocations it has not yet absorbed. */
async function absorbRekeys(session, state) {
  const keyring = new Map(session.keyring);
  for (const rekey of state.rekeys) {
    if (keyring.has(rekey.keyId)) continue;
    const wrap = rekey.wraps.find(w => w?.device === session.device.id);
    if (!wrap) continue;
    const raw = await unwrapFrom(session.device, wrap, rekeyContext(session.prism, wrap.device, rekey.epoch));
    keyring.set(rekey.keyId, await boundaryFromRaw(raw, session.shareable === true));
    raw.fill(0);
  }
  return keyring;
}

/** The boundary key this device must seal with. Refuses a stale key (Stitch.PrismId.boundaryKeyAdmitted). */
export async function currentBoundary(session) {
  const state = await resolvePrism(session.prism, session.log);
  const epochOf = id => (id === session.prism ? 0 : state.rekeys.find(r => r.keyId === id)?.epoch);
  const heldEpoch = Math.max(-1, ...[...session.keyring.keys()].map(epochOf).filter(Number.isSafeInteger));
  if (heldEpoch < 0 || !model['Stitch.PrismId.boundaryKeyAdmitted'](heldEpoch, state.boundary.epoch) || !session.keyring.has(state.boundary.keyId))
    refuse('stale-key', 'this device does not hold the current private boundary key');
  return { keyId: state.boundary.keyId, epoch: state.boundary.epoch, entry: session.keyring.get(state.boundary.keyId) };
}

// ---------------------------------------------------------------- sessions

function emptySession(prism, device, log) {
  return { prism, device, keyring: new Map(), log, shareable: true, personas: new Map(), personaDevices: new Map() };
}

/**
 * Create a prism on this device. No account, server or third party is involved.
 * The private boundary key never leaves a member device unwrapped.
 */
export async function createPrism(deviceOptions) {
  const device = await createDevice(deviceOptions);
  const genesis = await signRecord(device, { kind: KIND.genesis, device: device.record, nonce: toBase64Url(random(16)) });
  const prism = await kappa(genesis.body);
  const session = emptySession(prism, device, await logFromRecords([genesis]));
  session.keyring.set(prism, await boundaryFromRaw(random(32), true));
  return session;
}

/**
 * Revoke a device. By default the private boundary key rotates: a new key is
 * wrapped to every remaining member and recovery device (hybrid where they
 * advertise ML-KEM), never to the revoked device or to delegates. Binds the
 * revoked device made that this device knows of are kept. Persona keys of the
 * revoked device are revoked at every host this device can administer.
 */
export async function revokeDevice(session, deviceId, { rotate = true } = {}) {
  const state = await mayAdminister(session);
  const keep = [];
  for (const [id, e] of session.log) if (e.body.kind === KIND.bind && e.signer === deviceId) keep.push(id);
  const epoch = state.epoch + 1;
  const wraps = [];
  if (rotate) {
    const raw = random(32);
    for (const id of state.active) {
      if (id === deviceId || !model['Stitch.PrismId.receivesPrivateBoundary'](!boundaryRecipient(state.roles[id]))) continue;
      wraps.push({ device: id, ...await wrapTo(state.devices[id], raw, rekeyContext(session.prism, id, epoch)) });
    }
    raw.fill(0);
  }
  const envelope = await signRecord(session.device, { kind: KIND.revoke, prism: session.prism, device: deviceId, keep: keep.sort(), epoch, wraps });
  const log = await addRecord(session.log, envelope);
  let next = { ...session, log };
  next.keyring = await absorbRekeys(next, await resolvePrism(session.prism, log));
  next = await servicePersonas(next);
  return next;
}

// ---------------------------------------------------------------- out-of-band linking

const LINK_URI = 'prism-link:';

async function hmacKey(raw, usages) {
  return subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, usages);
}

/** Where the two devices meet on the bus. Only holders of the secret can derive it. */
export async function rendezvousTopic(secret) {
  return 'prism-rendezvous:' + (await kappa({ kind: KIND.rendezvous, secret })).slice(7);
}

/**
 * Six-digit code both devices show before the link is accepted. It binds the
 * secret to the joining device, so a device that read the QR code first shows
 * a code that does not match the one on the device the person is holding.
 */
export async function linkCode(secret, deviceRecord) {
  const digest = new Uint8Array(await subtle.digest('SHA-256', canonicalBytes({ kind: KIND.linkCode, secret, device: await kappa(deviceRecord) })));
  return String(new DataView(digest.buffer).getUint32(0) % 1000000).padStart(6, '0');
}

/**
 * Offer to link a new device. The returned URI is what the QR code (or NFC tag,
 * USB/serial line, or typed text) carries. The pending half stays here and is
 * used exactly once. A delegate offer names the actions the device may take.
 * Only a sharing (not hardened) member can offer a member link.
 */
export async function createLinkOffer(session, { now, ttl = 300000, role = 'member', scope = [] }) {
  await mayAdminister(session);
  if (role === 'recovery' || !bindShape({ role, scope })) refuse('offer', 'a member has no scope; a delegate needs at least one action');
  if (role === 'member') requireShareable(session, 'link a member');
  const offer = { kind: KIND.offer, prism: session.prism, role, scope: [...scope].sort(), secret: toBase64Url(random(32)), expires: now + ttl };
  return { offer, uri: LINK_URI + toBase64Url(canonicalBytes(offer)), pending: { offer, used: false } };
}

export function parseLinkUri(uri) {
  if (typeof uri !== 'string' || !uri.startsWith(LINK_URI)) refuse('offer', 'not a prism link');
  const offer = JSON.parse(decoder.decode(fromBase64Url(uri.slice(LINK_URI.length))));
  if (offer.kind !== KIND.offer || !isKappa(offer.prism) || !Number.isSafeInteger(offer.expires) || !bindShape(offer) ||
    offer.role === 'recovery' || typeof offer.secret !== 'string') refuse('offer', 'malformed link offer');
  return offer;
}

const requestProofBody = (prism, device) => ({ kind: KIND.request, prism, device });
const linkContext = offer => ({ salt: fromBase64Url(offer.secret), info: 'prism/link-wrap/1', aad: offer.prism });

/** New device: answer an offer it read out of band. */
export async function requestLink(device, offer) {
  const key = await hmacKey(fromBase64Url(offer.secret), ['sign']);
  const proof = await subtle.sign('HMAC', key, canonicalBytes(requestProofBody(offer.prism, device.record)));
  return { kind: KIND.request, prism: offer.prism, device: device.record, proof: toBase64Url(proof) };
}

/**
 * Existing member device: accept a link request. Refuses unless
 * Stitch.PrismId.linkOfferAccepted holds: the person confirmed the matching
 * six-digit code, the secret matches, the offer is unused and unexpired.
 * A member receives the keyring, hybrid-wrapped when it advertises ML-KEM;
 * a delegate receives no boundary key.
 */
export async function acceptLinkRequest(session, pending, request, { now, confirmCode }) {
  await mayAdminister(session);
  const { offer } = pending;
  let secretMatches = false, userConfirmed = false;
  if (request?.kind === KIND.request && request.prism === offer.prism) {
    try {
      checkDeviceRecord(request.device);
      if (request.device.class === 'recovery') refuse('offer', 'a recovery device is never linked by offer');
      const key = await hmacKey(fromBase64Url(offer.secret), ['verify']);
      secretMatches = await subtle.verify('HMAC', key, fromBase64Url(request.proof), canonicalBytes(requestProofBody(request.prism, request.device)));
      userConfirmed = typeof confirmCode === 'string' && confirmCode === await linkCode(offer.secret, request.device);
    } catch (error) { if (!(error instanceof PrismIdError)) throw error; }
  }
  if (!model['Stitch.PrismId.linkOfferAccepted'](userConfirmed, pending.used, secretMatches, offer.expires, now)) refuse('offer', 'link request refused');
  pending.used = true;
  const bind = await signRecord(session.device, { kind: KIND.bind, prism: session.prism, device: request.device, role: offer.role, scope: offer.scope });
  const log = await addRecord(session.log, bind);
  let wrap = null;
  if (model['Stitch.PrismId.receivesPrivateBoundary'](offer.role === 'delegate')) {
    requireShareable(session, 'link a member');
    wrap = await wrapTo(request.device, keyringBytes(session.keyring), linkContext(offer));
  }
  const response = { kind: KIND.response, prism: session.prism, records: [...log.values()], personas: personaRecords(session), wrap };
  return { session: await servicePersonas({ ...session, log }), response };
}

/** New device: finish linking. Verifies that the prism now lists this device with the offered role. */
export async function completeLink(device, offer, response) {
  if (response?.kind !== KIND.response || response.prism !== offer.prism) refuse('response', 'response is for another prism');
  const log = await logFromRecords(response.records);
  const state = await resolvePrism(offer.prism, log);
  if (!state.active.includes(device.id) || state.roles[device.id] !== offer.role) refuse('response', 'the prism did not bind this device');
  const session = emptySession(offer.prism, device, log);
  if (offer.role === 'member') {
    if (!response.wrap) refuse('response', 'member link without the private boundary');
    const bytes = await unwrapFrom(device, response.wrap, linkContext(offer));
    session.keyring = await keyringFromBytes(bytes, true);
    bytes.fill(0);
  }
  session.keyring = await absorbRekeys(session, state);
  await mergePersonaRecords(session, response.personas);
  return session;
}

// ---------------------------------------------------------------- threshold recovery

/** GF(2^8) with the AES polynomial; Shamir secret sharing over it. */
const GF_EXP = new Uint8Array(512), GF_LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) { GF_EXP[i] = x; GF_LOG[x] = i; x ^= (x << 1) ^ ((x & 0x80) ? 0x11b : 0); x &= 0xff; }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
}
const gfMul = (a, b) => (a && b ? GF_EXP[GF_LOG[a] + GF_LOG[b]] : 0);
const gfDiv = (a, b) => (a ? GF_EXP[GF_LOG[a] + 255 - GF_LOG[b]] : 0);

export function splitSecret(secret, threshold, count) {
  if (!Number.isSafeInteger(threshold) || !Number.isSafeInteger(count) || threshold < 1 || threshold > count || count > 255)
    refuse('recovery', 'threshold must be between 1 and the number of guardians (at most 255)');
  const shares = Array.from({ length: count }, (_, i) => ({ index: i + 1, bytes: new Uint8Array(secret.length) }));
  const coefficients = new Uint8Array(threshold);
  for (let b = 0; b < secret.length; b++) {
    coefficients[0] = secret[b];
    globalThis.crypto.getRandomValues(coefficients.subarray(1));
    for (const share of shares) {
      let y = 0;
      for (let c = threshold - 1; c >= 0; c--) y = gfMul(y, share.index) ^ coefficients[c];
      share.bytes[b] = y;
    }
  }
  coefficients.fill(0);
  return shares;
}

export function combineShares(shares) {
  const length = shares[0].bytes.length;
  const out = new Uint8Array(length);
  for (let b = 0; b < length; b++) {
    let y = 0;
    for (const i of shares) {
      let basis = 1;
      for (const j of shares) if (i !== j) basis = gfMul(basis, gfDiv(j.index, j.index ^ i.index));
      y ^= gfMul(i.bytes[b], basis);
    }
    out[b] = y;
  }
  return out;
}

const shareContext = (prism, index) => ({ salt: encoder.encode(prism), info: 'prism/recovery-share/1', aad: `${prism} ${index}` });

async function exportDeviceSecret(keys) {
  const secret = {
    sign: await subtle.exportKey('jwk', keys.signing.privateKey),
    agree: await subtle.exportKey('jwk', keys.agreement.privateKey)
  };
  if (keys.kem) secret.kem = toBase64Url(await subtle.exportKey('pkcs8', keys.kem.privateKey));
  return secret;
}

async function importDeviceSecret(record, secret) {
  const strip = ({ kty, crv, x, y, d }) => ({ kty, crv, x, y, d });
  const signingKey = await subtle.importKey('jwk', strip(secret.sign), SIGN, false, ['sign']);
  const agreementKey = await subtle.importKey('jwk', strip(secret.agree), AGREE, false, ['deriveBits']);
  const kemKey = secret.kem ? await subtle.importKey('pkcs8', fromBase64Url(secret.kem), KEM, false, ['decapsulateBits']) : null;
  return Object.freeze({ id: await kappa(record), record, signingKey, agreementKey, kemKey });
}

/**
 * Set up threshold recovery. A recovery device is created whose private keys
 * exist only as `threshold`-of-n shares, each sealed to one guardian: a device
 * of another prism the person trusts (a shared boundary), a spare device of
 * their own, or `{ paper: true }` for a share to print. The recovery device can
 * link and revoke but never acts at a host. Needs a sharing member, or the
 * current recovery device when rotating recovery.
 */
export async function createRecovery(session, { threshold, guardians }) {
  const state = await mayAdminister(session);
  requireShareable(session, 'set up recovery');
  if (!Array.isArray(guardians) || guardians.length < 1) refuse('recovery', 'at least one guardian is required');
  if (state.recovery && state.roles[session.device.id] !== 'recovery') refuse('recovery', 'recovery exists; only the recovery device may replace it');
  const keys = await newKeys(true);
  const device = await deviceFromKeys(keys, 'recovery', 'threshold-shares');
  const bind = await signRecord(session.device, { kind: KIND.bind, prism: session.prism, device: device.record, role: 'recovery', scope: [] });
  const log = await addRecord(session.log, bind);
  const after = await resolvePrism(session.prism, log);
  if (after.roles[device.id] !== 'recovery') refuse('recovery', 'the prism did not accept the recovery device');
  const secret = canonicalBytes({ kind: KIND.recoverySecret, prism: session.prism, device: device.record, keys: await exportDeviceSecret(keys), keyring: JSON.parse(decoder.decode(keyringBytes(session.keyring))).keys });
  const parts = splitSecret(secret, threshold, guardians.length);
  secret.fill(0);
  const shares = [];
  for (const [i, guardian] of guardians.entries()) {
    const part = parts[i];
    const body = { kind: KIND.recoveryShare, prism: session.prism, recovery: device.id, threshold, index: part.index };
    if (guardian?.paper === true) shares.push({ ...body, guardian: 'paper', share: toBase64Url(part.bytes) });
    else {
      checkDeviceRecord(guardian);
      shares.push({ ...body, guardian: await kappa(guardian), wrap: await wrapTo(guardian, part.bytes, shareContext(session.prism, part.index)) });
    }
    part.bytes.fill(0);
  }
  return { session: { ...session, log }, recovery: device.id, shares };
}

/**
 * Guardian: release a share to the person's new device. The guardian confirms
 * out of band that the new device is really the person's (a call, a meeting),
 * and compares the code from recoveryCode on both screens.
 */
export async function releaseShare(guardianDevice, share, newDeviceRecord) {
  if (share.kind !== KIND.recoveryShare || share.guardian !== guardianDevice.id) refuse('recovery', 'this share is not held by this guardian');
  const bytes = await unwrapFrom(guardianDevice, share.wrap, shareContext(share.prism, share.index));
  checkDeviceRecord(newDeviceRecord);
  const released = { kind: KIND.recoveryShare, prism: share.prism, recovery: share.recovery, threshold: share.threshold, index: share.index,
    guardian: await kappa(newDeviceRecord), wrap: await wrapTo(newDeviceRecord, bytes, shareContext(share.prism, share.index)) };
  bytes.fill(0);
  return released;
}

/** Code the new device shows and the guardian compares before releasing a share. */
export async function recoveryCode(prism, newDeviceRecord) {
  return linkCode(toBase64Url(encoder.encode(prism)), newDeviceRecord);
}

/**
 * Recover a prism on a new device from `threshold` shares. Refuses below the
 * threshold (Stitch.PrismId.thresholdMet). The recovered recovery device binds
 * the new device as a member and revokes every other device, which also stops
 * any revocations a thief made from counting. Pass `rotateRecovery` with new
 * guardians so the recovered secret is retired at once. Personas are carried
 * over when their host-held logs are supplied.
 */
export async function recoverPrism({ prism, records, shares, device, personas = {}, rotateRecovery }) {
  const log = await logFromRecords(records);
  const state = await resolvePrism(prism, log);
  if (!state.recovery) refuse('recovery', 'this prism has no active recovery device');
  const parts = [];
  for (const s of shares) {
    if (s.kind !== KIND.recoveryShare || s.prism !== prism || s.recovery !== state.recovery) continue;
    if (parts.some(p => p.index === s.index)) continue;
    const bytes = s.guardian === 'paper' ? fromBase64Url(s.share) : await unwrapFrom(device, s.wrap, shareContext(prism, s.index));
    parts.push({ index: s.index, threshold: s.threshold, bytes });
  }
  const threshold = parts[0]?.threshold ?? 0;
  if (parts.some(p => p.threshold !== threshold) || !model['Stitch.PrismId.thresholdMet'](threshold, parts.length)) refuse('recovery', 'not enough shares');
  const secretBytes = combineShares(parts.slice(0, threshold));
  for (const p of parts) p.bytes.fill(0);
  let secret;
  try { secret = JSON.parse(decoder.decode(secretBytes)); } catch { refuse('recovery', 'the shares do not combine to a recovery secret'); }
  secretBytes.fill(0);
  if (secret.kind !== KIND.recoverySecret || secret.prism !== prism || await kappa(secret.device) !== state.recovery) refuse('recovery', 'the shares belong to another recovery device');
  const recovery = await importDeviceSecret(secret.device, secret.keys);
  let custodian = emptySession(prism, recovery, log);
  for (const [id, raw] of Object.entries(secret.keyring)) custodian.keyring.set(id, await boundaryFromRaw(fromBase64Url(raw), true));
  custodian.keyring = await absorbRekeys(custodian, state);
  // Bind the new device, then revoke every other device; each revocation rotates the boundary.
  const bind = await signRecord(recovery, { kind: KIND.bind, prism, device: device.record, role: 'member', scope: [] });
  custodian.log = await addRecord(custodian.log, bind);
  // Revoke from the recovery device every other device ever linked, including ones a thief revoked:
  // once recovery revokes the thief, the thief's own revocations stop counting.
  const done = new Set([recovery.id, device.id]);
  for (let pending = [...state.active, ...state.revoked].filter(id => !done.has(id)); pending.length;) {
    for (const id of pending) { done.add(id); custodian = await revokeDevice(custodian, id); }
    const now = await resolvePrism(prism, custodian.log);
    pending = now.active.filter(id => !done.has(id));
  }
  custodian = await recoverPersonas(custodian, recovery, device, secret, personas);
  let result = { ...emptySession(prism, device, custodian.log), personas: custodian.personas, personaDevices: custodian.personaDevices };
  result.keyring = await absorbRekeys(result, await resolvePrism(prism, custodian.log));
  for (const [id, entry] of custodian.keyring) if (!result.keyring.has(id) && entry.raw) result.keyring.set(id, await boundaryFromRaw(entry.raw, true));
  let newShares = null;
  if (rotateRecovery) {
    const rotated = await createRecovery({ ...custodian, keyring: result.keyring }, rotateRecovery);
    custodian = await revokeDevice({ ...rotated.session, device: recovery, keyring: result.keyring }, recovery.id);
    result = { ...result, log: custodian.log };
    result.keyring = await absorbRekeys(result, await resolvePrism(prism, custodian.log));
    newShares = rotated.shares;
  }
  return { session: result, shares: newShares };
}

// ---------------------------------------------------------------- personas: one unlinkable id per host

/**
 * A persona is a prism of its own, one per host (audience). Each device has its
 * own non-extractable persona key for that host, so two hosts never see the
 * same prism id or device key and cannot link the person. Persona logs follow
 * the same rules (resolvePrism) as the main prism. The main prism records which
 * persona belongs to which host inside the private boundary only: the main log
 * travels sealed between member devices and is never given to a host.
 *
 * When the main prism has a recovery device, each persona also gets a persona
 * recovery device whose private keys are wrapped to the main recovery device.
 * No member keeps them, so a revoked member cannot hijack a persona.
 */
export async function ensurePersona(session, audience) {
  if (typeof audience !== 'string' || !audience) refuse('persona', 'audience must name a host');
  const state = await mayActForPersona(session);
  const existing = choosePersona(session, audience);
  if (existing) {
    if (!session.personaDevices.has(audience)) {
      const own = await createDevice({ deviceClass: session.device.record.class, protection: session.device.record.protection });
      const request = await signRecord(session.device, { kind: KIND.personaKey, prism: session.prism, audience, persona: existing.persona, device: own.record });
      const personaDevices = new Map(session.personaDevices).set(audience, own);
      return servicePersonas({ ...session, personaDevices, log: await addRecord(session.log, request) });
    }
    return session;
  }
  const own = await createDevice({ deviceClass: session.device.record.class, protection: session.device.record.protection });
  const genesis = await signRecord(own, { kind: KIND.genesis, device: own.record, nonce: toBase64Url(random(16)) });
  const persona = await kappa(genesis.body);
  let personaLog = await logFromRecords([genesis]);
  let recoverySeal = null;
  if (state.recovery) {
    const keys = await newKeys(true);
    const personaRecovery = await deviceFromKeys(keys, 'recovery', 'threshold-shares');
    personaLog = await addRecord(personaLog, await signRecord(own, { kind: KIND.bind, prism: persona, device: personaRecovery.record, role: 'recovery', scope: [] }));
    const secret = canonicalBytes({ kind: KIND.personaRecovery, persona, device: personaRecovery.record, keys: await exportDeviceSecret(keys) });
    recoverySeal = { recovery: state.recovery, ...await wrapTo(state.devices[state.recovery], secret, { salt: encoder.encode(persona), info: 'prism/persona-recovery/1', aad: persona }) };
    secret.fill(0);
  }
  const record = await signRecord(session.device, { kind: KIND.persona, prism: session.prism, audience, persona, recovery: recoverySeal });
  const keyRecord = await signRecord(session.device, { kind: KIND.personaKey, prism: session.prism, audience, persona, device: own.record });
  let log = await addRecord(session.log, record);
  log = await addRecord(log, keyRecord);
  const personas = new Map(session.personas).set(persona, personaLog);
  const personaDevices = new Map(session.personaDevices).set(audience, own);
  return servicePersonas({ ...session, log, personas, personaDevices });
}

async function mayActForPersona(session) {
  const state = await resolvePrism(session.prism, session.log);
  const id = session.device.id;
  if (!model['Stitch.PrismId.deviceMaySign'](state.active.includes(id), state.revoked.includes(id))) refuse('unauthorized', 'this device may not act for the prism');
  return state;
}

function personaEntries(session, kind) {
  return [...session.log.entries()].filter(([, e]) => e.body.kind === kind && e.body.prism === session.prism);
}

function choosePersona(session, audience) {
  const found = personaEntries(session, KIND.persona).filter(([, e]) => e.body.audience === audience).sort(byKey);
  return found.length ? found[0][1].body : null;
}

/** What a host needs to verify this device's actions: the persona id and log for that host. */
export async function personaFor(session, audience) {
  const chosen = choosePersona(session, audience);
  const own = session.personaDevices.get(audience);
  if (!chosen || !own) refuse('persona', 'no persona for this host yet; call ensurePersona');
  const log = session.personas.get(chosen.persona);
  const state = await resolvePrism(chosen.persona, log);
  if (!state.active.includes(own.id)) refuse('persona', 'this device is not yet bound in the persona; another member must sync first');
  return { persona: chosen.persona, records: [...log.values()] };
}

/** Sign an action for a host under this device's persona there. */
export async function signPersonaAction(session, audience, action, payload, { now }) {
  const { persona } = await personaFor(session, audience);
  return signAction({ prism: persona, device: session.personaDevices.get(audience) }, action, payload, { now, audience });
}

/**
 * Keep every persona this device can administer in step with the main prism:
 * bind persona keys requested by active main devices (with the same role and
 * scope), and revoke persona keys of devices the main prism revoked.
 */
async function servicePersonas(session) {
  if (!session.personas?.size) return session;
  const state = await resolvePrism(session.prism, session.log);
  const personas = new Map(session.personas);
  for (const [audience, own] of session.personaDevices) {
    const chosen = choosePersona(session, audience);
    if (!chosen || !personas.has(chosen.persona)) continue;
    let personaSession = { ...emptySession(chosen.persona, own, personas.get(chosen.persona)), shareable: false };
    let personaState = await resolvePrism(chosen.persona, personaSession.log);
    if (!personaState.active.includes(own.id) || !['member', 'recovery'].includes(personaState.roles[own.id])) continue;
    for (const [, e] of personaEntries(session, KIND.personaKey)) {
      if (e.body.persona !== chosen.persona) continue;
      const target = await kappa(e.body.device);
      const role = state.roles[e.signer];
      if (state.revoked.includes(e.signer)) {
        if (personaState.active.includes(target)) {
          personaSession = await revokeDevice(personaSession, target, { rotate: false });
          personaState = await resolvePrism(chosen.persona, personaSession.log);
        }
      } else if (role && role !== 'recovery' && !personaState.active.includes(target) && !personaState.revoked.includes(target)) {
        const bind = await signRecord(own, { kind: KIND.bind, prism: chosen.persona, device: e.body.device, role, scope: role === 'delegate' ? state.scopes[e.signer] : [] });
        personaSession.log = await addRecord(personaSession.log, bind);
        personaState = await resolvePrism(chosen.persona, personaSession.log);
      }
    }
    personas.set(chosen.persona, personaSession.log);
  }
  return { ...session, personas };
}

function personaRecords(session) {
  return Object.fromEntries([...(session.personas ?? new Map())].map(([id, log]) => [id, [...log.values()]]));
}

async function mergePersonaRecords(session, incoming) {
  if (!incoming || typeof incoming !== 'object') return;
  const known = new Set(personaEntries(session, KIND.persona).map(([, e]) => e.body.persona));
  for (const [id, records] of Object.entries(incoming)) {
    if (!known.has(id)) continue;
    const merged = mergeLogs(session.personas.get(id) ?? new Map(), await logFromRecords(records));
    await resolvePrism(id, merged);
    session.personas.set(id, merged);
  }
}

async function recoverPersonas(custodian, recovery, device, secret, hostLogs) {
  const personas = new Map(custodian.personas);
  const personaDevices = new Map();
  let log = custodian.log;
  for (const [, e] of personaEntries(custodian, KIND.persona)) {
    const { audience, persona, recovery: seal } = e.body;
    if (!seal || seal.recovery !== recovery.id || !hostLogs[persona]) continue;
    const bytes = await unwrapFrom(recovery, seal, { salt: encoder.encode(persona), info: 'prism/persona-recovery/1', aad: persona });
    const sealed = JSON.parse(decoder.decode(bytes));
    bytes.fill(0);
    const personaRecovery = await importDeviceSecret(sealed.device, sealed.keys);
    let personaSession = { ...emptySession(persona, personaRecovery, await logFromRecords(hostLogs[persona])), shareable: false };
    const before = await resolvePrism(persona, personaSession.log);
    if (!before.active.includes(personaRecovery.id)) continue;
    const own = await createDevice({ deviceClass: device.record.class, protection: device.record.protection });
    personaSession.log = await addRecord(personaSession.log, await signRecord(personaRecovery, { kind: KIND.bind, prism: persona, device: own.record, role: 'member', scope: [] }));
    for (const id of before.active) if (id !== personaRecovery.id) personaSession = await revokeDevice(personaSession, id, { rotate: false });
    log = await addRecord(log, await signRecord(device, { kind: KIND.personaKey, prism: custodian.prism, audience, persona, device: own.record }));
    personas.set(persona, personaSession.log);
    personaDevices.set(audience, own);
  }
  return { ...custodian, log, personas, personaDevices };
}

// ---------------------------------------------------------------- scoped actions and host admission

/**
 * Sign an action for a host (a foundry page, a native service, an embedded
 * sink). `audience` names the host, so the envelope is useless anywhere else;
 * a fresh nonce lets the host refuse replays. Prefer signPersonaAction, which
 * shows the host only that host's persona.
 */
export async function signAction(session, action, payload, { now, audience }) {
  if (typeof action !== 'string' || !action) refuse('action', 'action must be a name');
  if (typeof audience !== 'string' || !audience) refuse('action', 'action must name its audience');
  return signRecord(session.device, { kind: KIND.action, prism: session.prism, action, audience, payload, at: now, nonce: toBase64Url(random(16)) });
}

/**
 * Host side. Allowed only when Stitch.PrismId.actionFresh holds (this
 * audience, nonce not seen, issued within `window` of now) and
 * Stitch.PrismId.actionAllowed holds (an active member, or a delegate acting
 * inside its scope; a recovery device never acts). `seen` is the host's replay
 * set for the window. `prism` and `log` are the persona the device presented.
 */
export async function verifyAction(prism, log, envelope, { audience, now, window = 60000, seen = new Set() }) {
  const body = envelope?.body;
  if (body?.kind !== KIND.action || body.prism !== prism || !Number.isSafeInteger(body.at) || body.at < 0 || typeof body.nonce !== 'string')
    return { allowed: false, reason: 'not an action of this prism' };
  const state = await resolvePrism(prism, log);
  const id = envelope.signer;
  if (!state.devices[id] && !state.revoked.includes(id)) return { allowed: false, reason: 'unknown device' };
  if (!state.devices[id] || !await signatureValid(envelope, state.devices[id])) return { allowed: false, reason: 'signature or revocation' };
  const replayKey = `${id} ${body.nonce}`;
  if (!model['Stitch.PrismId.actionFresh'](body.audience === audience, !seen.has(replayKey), body.at, now, window))
    return { allowed: false, reason: 'audience, replay or time window' };
  const role = state.roles[id];
  const scoped = role !== 'member';
  const allowed = model['Stitch.PrismId.actionAllowed'](true, state.revoked.includes(id), scoped, role === 'delegate' && state.scopes[id].includes(body.action));
  if (allowed) seen.add(replayKey);
  return { allowed, reason: allowed ? 'ok' : 'scope', device: state.devices[id], role };
}

/**
 * Host policy for a device. A host that requires hardware-held keys admits a
 * device only when one of the host's own verifiers (Android key attestation,
 * Apple App Attest, a TPM quote, a secure-element certificate chain, each with
 * roots the host pins) confirms hardware protection of exactly this device's
 * signing key (Stitch.PrismId.attestationBinds). The record's `protection`
 * field is a claim, never evidence.
 */
export async function admitDevice(policy, deviceRecord, evidence, verifiers = {}) {
  checkDeviceRecord(deviceRecord);
  let attested = false;
  if (policy?.requiresHardwareKey === true && evidence && typeof verifiers[evidence.format] === 'function') {
    const result = await verifiers[evidence.format](evidence, deviceRecord);
    const keyMatches = !!result?.key && result.key.x === deviceRecord.sign.x && result.key.y === deviceRecord.sign.y && result.key.crv === 'P-256';
    attested = model['Stitch.PrismId.attestationBinds'](result?.hardware === true, keyMatches);
  }
  return hostAdmitsDevice(policy, { attestedHardwareKey: attested });
}

export function hostAdmitsDevice({ requiresHardwareKey = false } = {}, { attestedHardwareKey = false } = {}) {
  return model['Stitch.PrismId.hostAdmitsDevice'](requiresHardwareKey === true, attestedHardwareKey === true);
}

// ---------------------------------------------------------------- boundaries and sealed content

/**
 * A boundary record. One identity: private. Two or more: shared, which is
 * public to its members (Stitch.PrismId.boundaryShared). Published: public.
 */
export function describeBoundary({ members, published = false }) {
  const unique = [...new Set(members)].sort();
  if (!unique.length || !unique.every(isKappa)) refuse('boundary', 'members must be prism ids');
  const shared = model['Stitch.PrismId.boundaryShared'](unique.length);
  return { kind: KIND.boundary, members: unique, published, visibility: published ? 'public' : shared ? 'shared' : 'private' };
}

export function boundaryVisibleTo(boundary, prism) {
  return model['Stitch.PrismId.boundaryVisibleTo'](boundary.members.includes(prism), boundary.published === true);
}

/**
 * Sealed plaintext is padded (ISO/IEC 7816-4) to a power-of-two bucket of at
 * least 1 KiB, so observers learn only the bucket, not the exact size.
 */
export function padToBucket(bytes) {
  let size = 1024;
  while (size < bytes.length + 1) size *= 2;
  const out = new Uint8Array(size);
  out.set(bytes);
  out[bytes.length] = 0x80;
  return out;
}

export function unpad(bytes) {
  let end = bytes.length - 1;
  while (end >= 0 && bytes[end] === 0) end--;
  if (end < 0 || bytes[end] !== 0x80) refuse('padding', 'malformed padding');
  return bytes.subarray(0, end);
}

/** Seal a JSON value under the current private boundary key. The sealed object's kappa is its address. */
export async function sealPrivate(session, value) {
  const { keyId } = await currentBoundary(session);
  return sealWith(session, keyId, value);
}

async function sealWith(session, keyId, value) {
  const entry = session.keyring.get(keyId);
  if (!entry) refuse('stale-key', 'this device does not hold that boundary key');
  const sealed = { kind: KIND.sealed, boundary: 'private', key: keyId, ...await encryptWith(entry.seal, padToBucket(canonicalBytes(value)), session.prism) };
  return { address: await kappa(sealed), sealed };
}

/** Open sealed content with whichever key it names, including keys from before a rotation. */
export async function openPrivate(session, sealed) {
  const entry = session.keyring.get(sealed?.key);
  if (!entry) refuse('stale-key', 'this device does not hold that boundary key');
  return JSON.parse(decoder.decode(unpad(await decryptWith(entry.seal, sealed, session.prism))));
}

// ---------------------------------------------------------------- substrate sync

/** The sync topic for a boundary key. Only devices holding that key can derive it. */
export async function syncTopic(session, keyId) {
  const id = keyId ?? (await currentBoundary(session)).keyId;
  const entry = session.keyring.get(id);
  if (!entry) refuse('stale-key', 'this device does not hold that boundary key');
  return 'prism-sync:' + hex(await subtle.sign('HMAC', entry.topic, canonicalBytes({ kind: KIND.sync, prism: session.prism })));
}

/**
 * Publish this device's log and persona logs to its other member devices,
 * sealed in the private boundary. After a rotation, publish once under the
 * previous key so devices still listening there can take up the new key.
 */
export async function publishSync(session, bus, { keyId } = {}) {
  const id = keyId ?? (await currentBoundary(session)).keyId;
  const { sealed } = await sealWith(session, id, { kind: KIND.sync, prism: session.prism, records: [...session.log.values()], personas: personaRecords(session) });
  await bus.publish(await syncTopic(session, id), canonicalBytes(sealed));
}

/** Merge a sync message. Records that do not resolve for this prism are refused. */
export async function receiveSync(session, bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_SYNC_BYTES) refuse('sync', `sync message exceeds ${MAX_SYNC_BYTES} bytes`);
  const message = await openPrivate(session, JSON.parse(decoder.decode(bytes)));
  if (message.kind !== KIND.sync || message.prism !== session.prism) refuse('sync', 'sync message for another prism');
  const log = mergeLogs(session.log, await logFromRecords(message.records));
  if (log.size > MAX_LOG_RECORDS) refuse('log', `log exceeds ${MAX_LOG_RECORDS} records`);
  const state = await resolvePrism(session.prism, log);
  const next = { ...session, log, personas: new Map(session.personas) };
  next.keyring = await absorbRekeys(next, state);
  await mergePersonaRecords(next, message.personas);
  return servicePersonas(next);
}

/**
 * The bus contract the substrate implements: publish bytes to a topic and
 * deliver them to subscribers. This in-memory bus is for tests and single-page use.
 */
export function createMemoryBus() {
  const subscribers = new Map();
  return {
    async publish(topic, bytes) {
      for (const fn of [...(subscribers.get(topic) ?? [])]) await fn(new Uint8Array(bytes));
    },
    subscribe(topic, fn) {
      if (!subscribers.has(topic)) subscribers.set(topic, new Set());
      subscribers.get(topic).add(fn);
      return () => subscribers.get(topic)?.delete(fn);
    }
  };
}

// ---------------------------------------------------------------- the substrate bus

/*
 * The bus contract above on stitch's own transport, so a prism needs no
 * server of its own:
 *
 * - Across devices and origins: stitch's warm relay (ntfy, with stitch's relay
 *   framing, docs/relay-framing.md). The relay topic is hashed from the prism
 *   topic, which only holders of the secret can derive, so the relay sees an
 *   opaque name and sealed or HMAC-bound bytes. A message stays fetchable for
 *   the warm lifetime (30 minutes); the relay promises no retention.
 * - In one origin: BroadcastChannel, so tabs of one app hear each other at once.
 *
 * Every message carries its prism topic, a subscriber delivers only messages
 * for the topic it asked for, and a bus never hears itself. Bytes are
 * delivered as received; receiveSync and completeLink check every one.
 */
const BUS_KIND = 'prism/bus/1';
const BUS_TOPIC = /^prism-[a-z]+:[0-9a-f]{64}$/;
const WARM_SINCE = `${Math.floor(RELAY_LIFETIMES.warm / 60000)}m`;
const POLL_BYTES = 2 * 1024 * 1024;

function checkBusTopic(topic) {
  if (typeof topic !== 'string' || !BUS_TOPIC.test(topic)) throw new TypeError('not a prism topic');
  return topic;
}

/** The relay's name for a prism topic: a domain-separated hash, at most 64 characters as ntfy requires. */
export async function relayTopic(topic) {
  return 'prism-' + (await relayChannel(checkBusTopic(topic))).slice(7, 65);
}

/**
 * The bus. `relay` is the warm relay's base URL; `relay: null` keeps the bus
 * in this origin. Effects are injectable for tests and other hosts.
 */
export function createRelayBus({
  relay = 'https://ntfy.sh',
  fetch: fetchImpl = globalThis.fetch?.bind(globalThis),
  WebSocket: Socket = globalThis.WebSocket,
  BroadcastChannel: Channel = globalThis.BroadcastChannel
} = {}) {
  const from = newRelaySession();
  const wsBase = relay && relay.replace(/^http/, 'ws');
  const channels = new Map();
  const local = topic => {
    if (!Channel) return null;
    if (!channels.has(topic)) channels.set(topic, new Channel(`stitch:${topic}`));
    return channels.get(topic);
  };
  const envelope = (topic, bytes) => ({ kind: BUS_KIND, from, topic, bytes: toBase64Url(bytes) });
  // A message for this topic from another bus, or null.
  const unwrap = (topic, value) => value?.kind === BUS_KIND && value.topic === topic && value.from !== from && typeof value.bytes === 'string'
    ? fromBase64Url(value.bytes) : null;
  const assembler = topic => new RelayReassembler({ channelKey: topic, scope: 'warm' });
  // One bounded line of ntfy's JSON stream: a framed stitch message, or nothing.
  const frameOf = line => {
    if (typeof line !== 'string' || !line || line.length > RELAY_EVENT_BYTES) return null;
    const event = JSON.parse(line);
    return event.event === 'message' && typeof event.message === 'string' && !event.attachment ? event.message : null;
  };

  /** Resolves true when every frame was acknowledged by the relay (or there is no relay). Not a delivery receipt. */
  async function publish(topic, bytes) {
    checkBusTopic(topic);
    const value = envelope(topic, bytes);
    local(topic)?.postMessage(value);
    if (!relay || !fetchImpl) return true;
    const snapshot = snapshotRelayMessage(value);
    const { frames } = await frameRelayMessage(snapshot, { channelKey: topic, session: from, scope: 'warm' });
    const url = `${relay}/${await relayTopic(topic)}`;
    for (const body of frames) {
      const response = await fetchImpl(url, { method: 'POST', body, headers: { 'Content-Type': 'text/plain; charset=utf-8', Cache: 'yes' } });
      if (!response.ok) return false;
    }
    return true;
  }

  /** The messages other buses left on the relay for a topic within the warm lifetime, oldest first. */
  async function fetchTopic(topic) {
    checkBusTopic(topic);
    if (!relay || !fetchImpl) return [];
    const response = await fetchImpl(`${relay}/${await relayTopic(topic)}/json?poll=1&since=${WARM_SINCE}`);
    if (!response.ok) return [];
    const text = await response.text();
    if (text.length > POLL_BYTES) return [];
    const reassembler = assembler(topic), out = [];
    try {
      for (const line of text.split('\n')) {
        try {
          const frame = frameOf(line);
          const message = frame && unwrap(topic, await reassembler.accept(frame));
          if (message) out.push(message);
        } catch { /* a refused frame is skipped; the others still count */ }
      }
    } finally { reassembler.dispose(); }
    return out;
  }

  /**
   * Calls fn(bytes) for each message on the topic: those the relay still
   * holds, then new ones from the relay and from this origin. Returns a
   * function that stops it. A failing fn does not stop the subscription.
   */
  function subscribe(topic, fn) {
    checkBusTopic(topic);
    let open = true, socket = null, reassembler = null;
    const deliver = bytes => { if (open && bytes) Promise.resolve().then(() => fn(bytes)).catch(() => {}); };
    const channel = local(topic);
    const onLocal = event => deliver(unwrap(topic, event.data));
    channel?.addEventListener('message', onLocal);
    if (relay && fetchImpl) fetchTopic(topic).then(list => list.forEach(deliver), () => {});
    if (relay && Socket) {
      reassembler = assembler(topic);
      relayTopic(topic).then(name => {
        if (!open) return;
        socket = new Socket(`${wsBase}/${name}/ws`);
        socket.onmessage = async event => {
          try {
            const frame = frameOf(event.data);
            deliver(frame && unwrap(topic, await reassembler.accept(frame)));
          } catch { /* a refused frame is skipped */ }
        };
      }, () => {});
    }
    return () => {
      open = false;
      channel?.removeEventListener('message', onLocal);
      socket?.close();
      reassembler?.dispose();
    };
  }

  function close() {
    for (const channel of channels.values()) channel.close();
    channels.clear();
  }

  return { publish, subscribe, fetch: fetchTopic, close };
}
