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
 */
import { model } from './layer1-uor/generated-model.js';

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
  boundary: 'prism/boundary/1'
});

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
const publicJwk = ({ kty, crv, x, y }) => ({ crv, kty, x, y });

/**
 * A device holds two non-extractable private keys: one signs prism records,
 * one agrees keys for wrapping. Only its public record leaves the device.
 */
export async function createDevice() {
  const signing = await subtle.generateKey(SIGN, false, ['sign', 'verify']);
  const agreement = await subtle.generateKey(AGREE, false, ['deriveBits']);
  const record = {
    kind: KIND.device,
    sign: publicJwk(await subtle.exportKey('jwk', signing.publicKey)),
    agree: publicJwk(await subtle.exportKey('jwk', agreement.publicKey))
  };
  return Object.freeze({ id: await kappa(record), record, signingKey: signing.privateKey, agreementKey: agreement.privateKey });
}

function checkDeviceRecord(record) {
  const okKey = k => k && k.kty === 'EC' && k.crv === 'P-256' && typeof k.x === 'string' && typeof k.y === 'string' && Object.keys(k).length === 4;
  if (!record || record.kind !== KIND.device || !okKey(record.sign) || !okKey(record.agree) || Object.keys(record).length !== 3) refuse('device', 'malformed device record');
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

export async function logFromRecords(records) {
  let log = new Map();
  for (const r of records) log = await addRecord(log, r);
  return log;
}

/**
 * Resolve which devices may act for the prism.
 *
 * A bind is accepted only when Stitch.PrismId.bindAllowed holds: its signer is
 * linked, its signature verifies, it names this prism, and its signer has not
 * been revoked unless a revocation explicitly kept that bind. Revocation wins
 * over a concurrent bind: binds a revoked device made that its revoker did not
 * know of are dropped. Rotation (revoking the genesis device) keeps every bind
 * the revoker listed, so the remaining devices stay linked.
 */
export async function resolvePrism(prism, log) {
  const entries = [...log.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const geneses = [];
  for (const [, e] of entries) if (e?.body?.kind === KIND.genesis && await kappa(e.body) === prism) geneses.push(e);
  if (geneses.length !== 1) refuse('genesis', 'the log does not hold exactly one genesis for this prism');
  const genesis = geneses[0];
  const genesisDevice = genesis.body.device;
  if (!await signatureValid(genesis, genesisDevice)) refuse('genesis', 'genesis signature does not verify');

  const devices = new Map([[genesis.signer, genesisDevice]]);
  const binds = [], revokes = [];
  for (const [id, e] of entries) {
    const kind = e?.body?.kind;
    if (kind === KIND.bind) binds.push({ id, e });
    else if (kind === KIND.revoke) revokes.push({ id, e });
  }
  for (const { e } of binds) {
    try { const r = checkDeviceRecord(e.body.device); devices.set(await kappa(r), r); } catch (error) { if (!(error instanceof PrismIdError)) throw error; }
  }
  const verified = new Map();
  const verify = async (id, e) => {
    if (!verified.has(id)) verified.set(id, devices.has(e.signer) && await signatureValid(e, devices.get(e.signer)));
    return verified.get(id);
  };

  let linked = new Set([genesis.signer]);
  let revocations = new Map();
  for (let round = 0; round <= log.size + 1; round++) {
    // Revocations count only when signed by a linked device of this prism.
    const nextRevocations = new Map();
    for (const { id, e } of revokes) {
      if (e.body.prism !== prism || !linked.has(e.signer) || !await verify(id, e)) continue;
      const kept = nextRevocations.get(e.body.device) ?? new Set();
      for (const k of Array.isArray(e.body.keep) ? e.body.keep : []) kept.add(k);
      nextRevocations.set(e.body.device, kept);
    }
    const nextLinked = new Set([genesis.signer]);
    for (let grew = true; grew;) {
      grew = false;
      for (const { id, e } of binds) {
        const target = await kappa(e.body.device).catch(() => null);
        if (!target || nextLinked.has(target)) continue;
        const revocation = nextRevocations.get(e.signer);
        const signerRevoked = revocation !== undefined && !revocation.has(id);
        if (model['Stitch.PrismId.bindAllowed'](nextLinked.has(e.signer), signerRevoked, await verify(id, e), e.body.prism === prism)) {
          nextLinked.add(target); grew = true;
        }
      }
    }
    const same = nextLinked.size === linked.size && [...nextLinked].every(d => linked.has(d)) &&
      nextRevocations.size === revocations.size && [...nextRevocations.keys()].every(d => revocations.has(d));
    linked = nextLinked; revocations = nextRevocations;
    if (same) {
      const active = [...linked].filter(d => model['Stitch.PrismId.deviceMaySign'](true, revocations.has(d))).sort();
      return Object.freeze({
        prism,
        active,
        revoked: [...revocations.keys()].sort(),
        devices: Object.freeze(Object.fromEntries(active.map(d => [d, devices.get(d)])))
      });
    }
  }
  return refuse('resolve', 'device linkage did not settle');
}

export async function canSign(prism, log, deviceId) {
  const state = await resolvePrism(prism, log);
  return model['Stitch.PrismId.deviceMaySign'](state.active.includes(deviceId) || state.revoked.includes(deviceId), state.revoked.includes(deviceId));
}

// ---------------------------------------------------------------- sessions

/**
 * Create a prism on this device. No account, server or third party is involved.
 * The private boundary key never leaves a linked device unwrapped.
 */
export async function createPrism() {
  const device = await createDevice();
  const boundaryKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const genesis = await signRecord(device, { kind: KIND.genesis, device: device.record, nonce: toBase64Url(random(16)) });
  const prism = await kappa(genesis.body);
  return { prism, device, boundaryKey, log: await logFromRecords([genesis]) };
}

async function requireActive(session) {
  if (!await canSign(session.prism, session.log, session.device.id)) refuse('unauthorized', 'this device may not sign for the prism');
}

/** Revoke a device. Binds it made that this device knows of are kept. */
export async function revokeDevice(session, deviceId) {
  await requireActive(session);
  const keep = [];
  for (const [id, e] of session.log) if (e.body.kind === KIND.bind && e.signer === deviceId) keep.push(id);
  const envelope = await signRecord(session.device, { kind: KIND.revoke, prism: session.prism, device: deviceId, keep: keep.sort() });
  return { ...session, log: await addRecord(session.log, envelope) };
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
 * Offer to link a new device. The returned URI is what the QR code carries.
 * The pending half stays on this device and is used exactly once.
 */
export async function createLinkOffer(session, { now, ttl = 300000 }) {
  await requireActive(session);
  const ephemeral = await subtle.generateKey(AGREE, false, ['deriveBits']);
  const offer = {
    kind: KIND.offer,
    prism: session.prism,
    secret: toBase64Url(random(32)),
    agree: publicJwk(await subtle.exportKey('jwk', ephemeral.publicKey)),
    expires: now + ttl
  };
  return { offer, uri: LINK_URI + toBase64Url(canonicalBytes(offer)), pending: { offer, ephemeralKey: ephemeral.privateKey, used: false } };
}

export function parseLinkUri(uri) {
  if (typeof uri !== 'string' || !uri.startsWith(LINK_URI)) refuse('offer', 'not a prism link');
  const offer = JSON.parse(decoder.decode(fromBase64Url(uri.slice(LINK_URI.length))));
  if (offer.kind !== KIND.offer || !isKappa(offer.prism) || !Number.isSafeInteger(offer.expires)) refuse('offer', 'malformed link offer');
  return offer;
}

const requestProofBody = (prism, device) => ({ kind: KIND.request, prism, device });

/** New device: answer an offer it read out of band. */
export async function requestLink(device, offer) {
  const key = await hmacKey(fromBase64Url(offer.secret), ['sign']);
  const proof = await subtle.sign('HMAC', key, canonicalBytes(requestProofBody(offer.prism, device.record)));
  return { kind: KIND.request, prism: offer.prism, device: device.record, proof: toBase64Url(proof) };
}

async function wrapKey(privateKey, publicJwkValue, secret) {
  const peer = await subtle.importKey('jwk', { ...publicJwkValue, ext: true }, AGREE, false, []);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: peer }, privateKey, 256);
  const material = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: fromBase64Url(secret), info: encoder.encode('prism/link-wrap/1') },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/**
 * Existing device: accept a link request. Refuses unless
 * Stitch.PrismId.linkOfferAccepted holds for the secret, single use and expiry.
 */
export async function acceptLinkRequest(session, pending, request, { now }) {
  await requireActive(session);
  const { offer } = pending;
  let secretMatches = false;
  if (request?.kind === KIND.request && request.prism === offer.prism) {
    try {
      checkDeviceRecord(request.device);
      const key = await hmacKey(fromBase64Url(offer.secret), ['verify']);
      secretMatches = await subtle.verify('HMAC', key, fromBase64Url(request.proof), canonicalBytes(requestProofBody(request.prism, request.device)));
    } catch (error) { if (!(error instanceof PrismIdError)) throw error; }
  }
  if (!model['Stitch.PrismId.linkOfferAccepted'](secretMatches, pending.used, offer.expires, now)) refuse('offer', 'link request refused');
  pending.used = true;
  const bind = await signRecord(session.device, { kind: KIND.bind, prism: session.prism, device: request.device });
  const log = await addRecord(session.log, bind);
  const wrapping = await wrapKey(pending.ephemeralKey, request.device.agree, offer.secret);
  const iv = random(12);
  const raw = await subtle.exportKey('raw', session.boundaryKey);
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(session.prism) }, wrapping, raw);
  const response = { kind: KIND.response, prism: session.prism, records: [...log.values()], wrap: { iv: toBase64Url(iv), ciphertext: toBase64Url(ciphertext) } };
  return { session: { ...session, log }, response };
}

/** New device: finish linking. Verifies that the prism now lists this device. */
export async function completeLink(device, offer, response) {
  if (response?.kind !== KIND.response || response.prism !== offer.prism) refuse('response', 'response is for another prism');
  const log = await logFromRecords(response.records);
  const state = await resolvePrism(offer.prism, log);
  if (!state.active.includes(device.id)) refuse('response', 'the prism did not bind this device');
  const wrapping = await wrapKey(device.agreementKey, offer.agree, offer.secret);
  const raw = await subtle.decrypt({ name: 'AES-GCM', iv: fromBase64Url(response.wrap.iv), additionalData: encoder.encode(offer.prism) }, wrapping, fromBase64Url(response.wrap.ciphertext));
  const boundaryKey = await subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  return { prism: offer.prism, device, boundaryKey, log };
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

/** Seal a JSON value in the private boundary. The sealed object's kappa is its address. */
export async function sealPrivate(session, value) {
  const iv = random(12);
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(session.prism) }, session.boundaryKey, canonicalBytes(value));
  const sealed = { kind: KIND.sealed, boundary: 'private', iv: toBase64Url(iv), ciphertext: toBase64Url(ciphertext) };
  return { address: await kappa(sealed), sealed };
}

export async function openPrivate(session, sealed) {
  const bytes = await subtle.decrypt({ name: 'AES-GCM', iv: fromBase64Url(sealed.iv), additionalData: encoder.encode(session.prism) }, session.boundaryKey, fromBase64Url(sealed.ciphertext));
  return JSON.parse(decoder.decode(bytes));
}

// ---------------------------------------------------------------- substrate sync

/** The sync topic is derived from the private boundary key, so only linked devices can find it. */
export async function syncTopic(session) {
  const key = await hmacKey(await subtle.exportKey('raw', session.boundaryKey), ['sign']);
  return 'prism-sync:' + hex(await subtle.sign('HMAC', key, canonicalBytes({ kind: KIND.sync, prism: session.prism })));
}

/** Publish this device's log to its other devices, sealed in the private boundary. */
export async function publishSync(session, bus) {
  const { sealed } = await sealPrivate(session, { kind: KIND.sync, prism: session.prism, records: [...session.log.values()] });
  await bus.publish(await syncTopic(session), canonicalBytes(sealed));
}

/** Merge a sync message. Records that do not resolve for this prism are refused. */
export async function receiveSync(session, bytes) {
  const message = await openPrivate(session, JSON.parse(decoder.decode(bytes)));
  if (message.kind !== KIND.sync || message.prism !== session.prism) refuse('sync', 'sync message for another prism');
  const log = mergeLogs(session.log, await logFromRecords(message.records));
  await resolvePrism(session.prism, log);
  return { ...session, log };
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

// ---------------------------------------------------------------- recovery

/**
 * Recovery: a prism outlives every device it was made on.
 *
 * A recovery device is an ordinary prism device (prism/device/1), linked
 * through the same out-of-band link flow as any other device, whose private
 * keys are kept outside every browser: sealed in an escrow object under a
 * key derived from a short recovery code the owner writes down. With the code
 * and its escrow, any new device links itself to the prism, receives the
 * private boundary, and carries on. Every authorization decision is still
 * taken by Stitch.PrismId (bindAllowed, linkOfferAccepted, deviceMaySign)
 * above; recovery adds no rule of its own.
 *
 * The code is the escrow key's 32-byte seed and three check bytes (the start
 * of its SHA-256), in Crockford base32: 56 characters, written in groups of
 * four. Readers ignore spaces, hyphens and case, read I and L as 1 and O as 0,
 * and refuse a code whose check bytes differ.
 *
 * The escrow is public-safe: AES-GCM ciphertext bound to its locator. It can
 * sit in any content-addressed store (its kappa is its address) and be found
 * by its locator, which is derived from the seed and reveals nothing about it.
 * It carries the log as it stood when the code was made, so recovery needs no
 * other service; later records arrive by sync.
 */
export const RECOVERY_KIND = Object.freeze({
  escrow: 'prism/recovery-escrow/1',
  sealed: 'prism/recovery/1',
  locator: 'prism/recovery-locator/1'
});


// ---------------------------------------------------------------- the code

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export async function encodeCode(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) refuse('code', 'a recovery seed is 32 bytes');
  const bytes = [...seed, ...new Uint8Array(await subtle.digest('SHA-256', seed)).slice(0, 3)];
  const bits = bytes.map(b => b.toString(2).padStart(8, '0')).join('');
  const chars = bits.match(/.{5}/g).map(five => CROCKFORD[parseInt(five, 2)]).join('');
  return chars.match(/.{4}/g).join(' ');
}

export async function decodeCode(text) {
  const clean = String(text).toUpperCase().replace(/[\s-]/g, '').replace(/[IL]/g, '1').replace(/O/g, '0');
  if (!/^[0-9A-HJKMNP-TV-Z]{56}$/.test(clean)) refuse('code', 'a recovery code is 56 letters and digits');
  const bits = [...clean].map(c => CROCKFORD.indexOf(c).toString(2).padStart(5, '0')).join('');
  const bytes = Uint8Array.from(bits.match(/.{8}/g), byte => parseInt(byte, 2));
  const seed = bytes.slice(0, 32);
  const check = new Uint8Array(await subtle.digest('SHA-256', seed)).slice(0, 3);
  if (check.some((b, i) => b !== bytes[32 + i])) refuse('code', 'the recovery code has a typo');
  return seed;
}

// ---------------------------------------------------------------- keys from the seed

async function derive(seed, info, length) {
  const material = await subtle.importKey('raw', seed, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: encoder.encode(info) }, material, length * 8));
}

async function escrowKey(seed) {
  return subtle.importKey('raw', await derive(seed, 'prism/recovery/key/1', 32), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** Where the escrow is kept: derived from the seed, revealing nothing about it. */
export async function recoveryLocator(seed) {
  return kappa({ kind: RECOVERY_KIND.locator, locator: toBase64Url(await derive(seed, 'prism/recovery/locator/1', 32)) });
}

// ---------------------------------------------------------------- making a code

/** A device whose private keys can be sealed into an escrow. Used only for recovery. */
async function createEscrowedDevice() {
  const signing = await subtle.generateKey(SIGN, true, ['sign', 'verify']);
  const agreement = await subtle.generateKey(AGREE, true, ['deriveBits']);
  const record = {
    kind: KIND.device,
    sign: publicJwk(await subtle.exportKey('jwk', signing.publicKey)),
    agree: publicJwk(await subtle.exportKey('jwk', agreement.publicKey))
  };
  return { id: await kappa(record), record, signingKey: signing.privateKey, agreementKey: agreement.privateKey };
}

/** Link `device` to the prism of `session`, entirely on this page: the ordinary link flow. */
async function linkLocally(session, device, now) {
  const { uri, pending } = await createLinkOffer(session, { now });
  const offer = parseLinkUri(uri);
  const request = await requestLink(device, offer);
  const accepted = await acceptLinkRequest(session, pending, request, { now });
  const joined = await completeLink(device, offer, accepted.response);
  return { session: accepted.session, joined };
}

/**
 * Make a recovery code for the prism of `session` (an active device). Links a
 * new recovery device, then seals its private keys, the private boundary and
 * the log in an escrow. Returns the code (show it once, store it nowhere),
 * the escrow (keep it anywhere; its locator finds it) and the session with
 * the recovery device's bind in its log.
 */
export async function createRecovery(session, { now }) {
  const recoveryDevice = await createEscrowedDevice();
  const { session: next, joined } = await linkLocally(session, recoveryDevice, now);
  const seed = random(32);
  const sealed = {
    kind: RECOVERY_KIND.sealed,
    prism: next.prism,
    device: recoveryDevice.record,
    sign: toBase64Url(await subtle.exportKey('pkcs8', recoveryDevice.signingKey)),
    agree: toBase64Url(await subtle.exportKey('pkcs8', recoveryDevice.agreementKey)),
    boundary: toBase64Url(await subtle.exportKey('raw', joined.boundaryKey)),
    records: [...joined.log.values()]
  };
  const locator = await recoveryLocator(seed);
  const iv = random(12);
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(locator) }, await escrowKey(seed), canonicalBytes(sealed));
  const escrow = { kind: RECOVERY_KIND.escrow, locator, iv: toBase64Url(iv), ciphertext: toBase64Url(ciphertext) };
  const code = await encodeCode(seed);
  seed.fill(0);
  return { code, escrow, device: recoveryDevice.id, session: next };
}

// ---------------------------------------------------------------- using a code

/** Open an escrow with its code: the recovery device's session. */
export async function openRecovery(code, escrow) {
  const seed = await decodeCode(code);
  const locator = await recoveryLocator(seed);
  if (escrow?.kind !== RECOVERY_KIND.escrow || escrow.locator !== locator) refuse('escrow', 'the escrow is not this code\'s');
  let sealed;
  try {
    const bytes = await subtle.decrypt({ name: 'AES-GCM', iv: fromBase64Url(escrow.iv), additionalData: encoder.encode(locator) }, await escrowKey(seed), fromBase64Url(escrow.ciphertext));
    sealed = JSON.parse(decoder.decode(bytes));
  } catch (error) {
    if (error instanceof PrismIdError) throw error;
    refuse('escrow', 'the escrow does not open with this code');
  } finally {
    seed.fill(0);
  }
  if (sealed?.kind !== RECOVERY_KIND.sealed) refuse('escrow', 'the escrow does not hold a recovery device');
  const device = {
    id: await kappa(sealed.device),
    record: sealed.device,
    signingKey: await subtle.importKey('pkcs8', fromBase64Url(sealed.sign), SIGN, false, ['sign']),
    agreementKey: await subtle.importKey('pkcs8', fromBase64Url(sealed.agree), AGREE, false, ['deriveBits'])
  };
  const boundaryKey = await subtle.importKey('raw', fromBase64Url(sealed.boundary), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  const log = await logFromRecords(sealed.records);
  await resolvePrism(sealed.prism, log);
  return { prism: sealed.prism, device, boundaryKey, log };
}

/**
 * Link `device` (this browser's own, non-extractable) to the prism with a
 * recovery code. `log` may add records newer than the escrow's, from sync or
 * any store; a recovery device revoked there cannot link anything. Returns the
 * new device's session.
 */
export async function recoverOnto(code, escrow, device, { now, log } = {}) {
  const recovery = await openRecovery(code, escrow);
  if (log) {
    for (const [k, v] of log) recovery.log.set(k, v);
  }
  const { joined } = await linkLocally(recovery, device, now);
  return joined;
}
