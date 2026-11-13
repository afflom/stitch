import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import {
  canonicalJson, kappa, isKappa, createPrism, createDevice, checkDeviceRecord, resolvePrism, canSign, revokeDevice,
  createLinkOffer, parseLinkUri, requestLink, acceptLinkRequest, completeLink, rendezvousTopic, linkCode,
  mergeLogs, logRoot, addRecord, logFromRecords, describeBoundary, boundaryVisibleTo, sealPrivate, openPrivate,
  currentBoundary, syncTopic, publishSync, receiveSync, createMemoryBus, signAction, verifyAction, hostAdmitsDevice,
  PrismIdError, KIND, MAX_LOG_RECORDS, MAX_SYNC_BYTES, postQuantumAvailable, hardenSession, createRecovery, releaseShare,
  recoveryCode, recoverPrism, splitSecret, combineShares, ensurePersona, personaFor, signPersonaAction, admitDevice, padToBucket, unpad
} from '../src/prism-id.js';

const NOW = 1_800_000_000_000;
const HOST = 'https://foundry.uor.foundation';
const AT = { audience: HOST, now: NOW };
const vectors = JSON.parse(readFileSync(new URL('./fixtures/prism-id-vectors.json', import.meta.url)));

/** Link a device the way a person does: scan, compare the six-digit code on both screens, confirm. */
async function link(session, { now = NOW, role = 'member', scope = [], device } = {}) {
  const { uri, pending } = await createLinkOffer(session, { now, role, scope });
  const offer = parseLinkUri(uri);
  const joining = device ?? await createDevice();
  const request = await requestLink(joining, offer);
  const shownOnNewDevice = await linkCode(offer.secret, joining.record);
  const accepted = await acceptLinkRequest(session, pending, request, { now: now + 1000, confirmCode: shownOnNewDevice });
  const joined = await completeLink(joining, offer, accepted.response);
  return { origin: accepted.session, joined, offer, pending, request };
}

async function capture(bus, session, options) {
  let got;
  const topic = await syncTopic(session, options?.keyId);
  const stop = bus.subscribe(topic, bytes => { got = bytes; });
  await publishSync(session, bus, options);
  stop();
  return got;
}

test('canonical JSON follows uor-addr: UTF-8 member order, integers only, NFC strings', async () => {
  assert.equal(canonicalJson({ b: 1, a: [true, null, 'x'], '\u00e9': 2, Z: -3 }), '{"Z":-3,"a":[true,null,"x"],"b":1,"\u00e9":2}');
  // UTF-16 order would put U+1F600 first; UTF-8 byte order puts U+FF61 first.
  assert.equal(canonicalJson({ '\u{1F600}': 1, '\uFF61': 2 }), '{"\uFF61":2,"\u{1F600}":1}');
  assert.equal(canonicalJson('a"\\\b\t\n\f\r\u0001/\u007f'), '"a\\"\\\\\\b\\t\\n\\f\\r\\u0001/\u007f"');
  for (const bad of [1.5, -0, 2 ** 53, NaN, 'e\u0301', { k: undefined }, new Date(0), '\ud800'])
    assert.throws(() => canonicalJson(bad), PrismIdError, String(bad));
  assert.equal(await kappa({}), 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a');
  assert.equal(await kappa({ b: 1, a: 2 }), await kappa({ a: 2, b: 1 }));
});

test('published conformance vectors hold, so any runtime can check its own implementation', async () => {
  for (const v of vectors.canonical) {
    assert.equal(canonicalJson(v.value), v.canonical, v.name);
    assert.equal(await kappa(v.value), v.kappa, v.name);
  }
  for (const v of vectors.refused) assert.throws(() => canonicalJson(v.value), PrismIdError, v.name);
  const log = await logFromRecords(vectors.prism.records);
  const state = await resolvePrism(vectors.prism.id, log);
  assert.deepEqual(state.active, vectors.prism.active);
  assert.deepEqual(state.roles, vectors.prism.roles);
  assert.deepEqual(state.scopes, vectors.prism.scopes);
});

test('an independent Python implementation agrees on every canonical vector', () => {
  const run = spawnSync('python3', ['-I', 'scripts/verify-prism-id-vectors.py', 'tests/fixtures/prism-id-vectors.json'], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr + run.stdout);
  assert.match(run.stdout, /^verified \d+ canonical vectors and \d+ refusals$/m);
});

test('a prism comes into being without any account; its id is the kappa of its genesis', async () => {
  const session = await createPrism();
  assert.ok(isKappa(session.prism));
  const [genesis] = session.log.values();
  assert.equal(genesis.body.kind, KIND.genesis);
  assert.equal(await kappa(genesis.body), session.prism);
  const state = await resolvePrism(session.prism, session.log);
  assert.deepEqual(state.active, [session.device.id]);
  assert.deepEqual(state.roles, { [session.device.id]: 'member' });
  assert.deepEqual(state.boundary, { epoch: 0, keyId: session.prism });
  assert.equal(await canSign(session.prism, session.log, session.device.id), true);
  assert.notEqual((await createPrism()).prism, session.prism);
});

test('every device class uses the same record; keys are non-extractable and claims are bounded', async () => {
  for (const [deviceClass, protection] of [['browser', 'software'], ['native', 'platform'], ['mobile', 'platform'], ['embedded', 'secure-element']]) {
    const device = await createDevice({ deviceClass, protection });
    assert.equal(device.signingKey.extractable, false);
    assert.equal(device.agreementKey.extractable, false);
    assert.equal(device.id, await kappa(device.record));
    const fields = ['agree', 'class', 'kind', 'protection', 'sign', ...(await postQuantumAvailable() ? ['kem'] : [])].sort();
    assert.deepEqual(Object.keys(device.record).sort(), fields);
    assert.equal(checkDeviceRecord(device.record), device.record);
  }
  await assert.rejects(createDevice({ deviceClass: 'toaster' }), PrismIdError);
  await assert.rejects(createDevice({ protection: 'trust-me' }), PrismIdError);
  const device = await createDevice();
  assert.throws(() => checkDeviceRecord({ ...device.record, extra: 1 }), PrismIdError);
});

test('a mobile app and a native install join as members and receive the private boundary', async () => {
  const session = await createPrism();
  const secret = await sealPrivate(session, { note: 'only my devices' });
  const phone = await link(session, { device: await createDevice({ deviceClass: 'mobile', protection: 'platform' }) });
  const desktop = await link(phone.origin, { device: await createDevice({ deviceClass: 'native', protection: 'platform' }) });
  const state = await resolvePrism(session.prism, desktop.origin.log);
  assert.deepEqual(state.active, [session.device.id, phone.joined.device.id, desktop.joined.device.id].sort());
  assert.equal(state.roles[desktop.joined.device.id], 'member');
  assert.deepEqual(await openPrivate(phone.joined, secret.sealed), { note: 'only my devices' });
  assert.deepEqual(await openPrivate(desktop.joined, secret.sealed), { note: 'only my devices' });
  assert.equal(await logRoot(desktop.origin.log), await logRoot(desktop.joined.log));
});

test('the link needs the person to confirm the code shown on the joining device', async () => {
  const session = await createPrism();
  const { uri, pending } = await createLinkOffer(session, { now: NOW });
  const offer = parseLinkUri(uri);
  const mine = await createDevice();
  const thief = await createDevice();
  // Someone photographs the QR code and answers first. Their code differs from the one on the person's device.
  const stolen = await requestLink(thief, offer);
  const shownToPerson = await linkCode(offer.secret, mine.record);
  assert.notEqual(await linkCode(offer.secret, thief.record), shownToPerson);
  await assert.rejects(acceptLinkRequest(session, pending, stolen, { now: NOW, confirmCode: shownToPerson }), /link request refused/);
  await assert.rejects(acceptLinkRequest(session, pending, await requestLink(mine, offer), { now: NOW }), /link request refused/);
  assert.equal(pending.used, false);
  const accepted = await acceptLinkRequest(session, pending, await requestLink(mine, offer), { now: NOW, confirmCode: shownToPerson });
  assert.ok((await resolvePrism(session.prism, accepted.session.log)).active.includes(mine.id));
  assert.match(shownToPerson, /^\d{6}$/);
});

test('the offer is single use, expires, and refuses a request without the secret', async () => {
  const session = await createPrism();
  const { uri, pending } = await createLinkOffer(session, { now: NOW, ttl: 1000 });
  const offer = parseLinkUri(uri);
  const device = await createDevice();
  const request = await requestLink(device, offer);
  const confirmCode = await linkCode(offer.secret, device.record);
  await assert.rejects(acceptLinkRequest(session, pending, request, { now: NOW + 1000, confirmCode }), /link request refused/);
  const forged = await requestLink(device, { ...offer, secret: 'A'.repeat(43) });
  await assert.rejects(acceptLinkRequest(session, pending, forged, { now: NOW, confirmCode }), /link request refused/);
  await acceptLinkRequest(session, pending, request, { now: NOW, confirmCode });
  await assert.rejects(acceptLinkRequest(session, pending, request, { now: NOW, confirmCode }), /link request refused/);
  const stranger = await createPrism();
  await assert.rejects(completeLink(await createDevice(), { ...offer, prism: stranger.prism }, { kind: KIND.response, prism: stranger.prism, records: [...stranger.log.values()] }), /did not bind this device/);
  assert.throws(() => parseLinkUri('prism-link:' + Buffer.from('{"kind":"x"}').toString('base64url')), /malformed link offer/);
});

test('an embedded device joins as a scoped delegate and never holds the private boundary', async () => {
  const session = await createPrism();
  const sensor = await createDevice({ deviceClass: 'embedded', protection: 'secure-element' });
  const { origin, joined } = await link(session, { device: sensor, role: 'delegate', scope: ['telemetry/write'] });
  assert.equal(joined.keyring.size, 0);
  const state = await resolvePrism(session.prism, origin.log);
  assert.equal(state.roles[sensor.id], 'delegate');
  assert.deepEqual(state.scopes[sensor.id], ['telemetry/write']);
  const inScope = await signAction(joined, 'telemetry/write', { celsius: 21 }, { now: NOW, audience: HOST });
  assert.equal((await verifyAction(session.prism, origin.log, inScope, AT)).allowed, true);
  const outOfScope = await signAction(joined, 'profile/update', { name: 'x' }, { now: NOW, audience: HOST });
  assert.equal((await verifyAction(session.prism, origin.log, outOfScope, AT)).allowed, false);
  await assert.rejects(sealPrivate(joined, { x: 1 }), /current private boundary key/);
  await assert.rejects(createLinkOffer(joined, { now: NOW }), /may not administer/);
  await assert.rejects(revokeDevice(joined, session.device.id), /may not administer/);
  await assert.rejects(createLinkOffer(origin, { now: NOW, role: 'delegate', scope: [] }), /delegate needs/);
});

test('a delegate cannot bind a device even with a valid signature', async () => {
  const session = await createPrism();
  const { origin, joined } = await link(session, { role: 'delegate', scope: ['telemetry/write'] });
  const rogue = await createDevice();
  const body = { kind: KIND.bind, prism: session.prism, device: rogue.record, role: 'member', scope: [] };
  const signature = await globalThis.crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, joined.device.signingKey, new TextEncoder().encode(canonicalJson(body)));
  const forgedBind = { body, signer: joined.device.id, signature: Buffer.from(signature).toString('base64url') };
  const state = await resolvePrism(session.prism, await addRecord(origin.log, forgedBind));
  assert.equal(state.active.includes(rogue.id), false);
});

test('an unlinked device cannot bind devices or revoke', async () => {
  const session = await createPrism();
  const outsider = await createPrism();
  const forged = { ...session, device: outsider.device };
  await assert.rejects(revokeDevice(forged, session.device.id), /may not administer/);
  await assert.rejects(createLinkOffer(forged, { now: NOW }), /may not administer/);
  const { joined } = await link(outsider);
  const state = await resolvePrism(session.prism, mergeLogs(session.log, joined.log));
  assert.deepEqual(state.active, [session.device.id]);
});

test('revocation rotates the private boundary key away from the revoked device', async () => {
  const bus = createMemoryBus();
  const session = await createPrism();
  const phone = await link(session);
  const laptop = await link(phone.origin);
  let origin = laptop.origin, phoneSession = phone.joined, laptopSession = laptop.joined;
  phoneSession = await receiveSync(phoneSession, await capture(bus, origin));
  const before = await syncTopic(phoneSession);
  // The laptop is stolen. The phone revokes it; the revocation carries a new key wrapped to the remaining members.
  const revokedByPhone = await revokeDevice(phoneSession, laptopSession.device.id);
  const state = await resolvePrism(session.prism, revokedByPhone.log);
  assert.equal(state.boundary.epoch, 1);
  assert.deepEqual(state.revoked, [laptopSession.device.id]);
  assert.deepEqual(state.rekeys[0].wraps.map(w => w.device).sort(), [session.device.id, phoneSession.device.id].sort());
  const after = await syncTopic(revokedByPhone);
  assert.notEqual(after, before);
  // The origin device still listens on the old topic; one publish there hands it the new key.
  origin = await receiveSync(origin, await capture(bus, revokedByPhone, { keyId: session.prism }));
  assert.equal(await syncTopic(origin), after);
  const fresh = await sealPrivate(origin, { after: 'rotation' });
  assert.equal(fresh.sealed.key, state.boundary.keyId);
  assert.deepEqual(await openPrivate(revokedByPhone, fresh.sealed), { after: 'rotation' });
  // The revoked laptop sees the log but cannot take up the new key, seal, or open new content.
  laptopSession = await receiveSync(laptopSession, await capture(bus, revokedByPhone, { keyId: session.prism }));
  assert.equal(laptopSession.keyring.has(state.boundary.keyId), false);
  await assert.rejects(openPrivate(laptopSession, fresh.sealed), /does not hold/);
  await assert.rejects(sealPrivate(laptopSession, { x: 1 }), /current private boundary key/);
  await assert.rejects(currentBoundary(laptopSession), /current private boundary key/);
  assert.equal(await canSign(session.prism, laptopSession.log, laptopSession.device.id), false);
});

test('rotation keeps the devices the revoker knew, and revocation wins over a later bind', async () => {
  const session = await createPrism();
  const { origin, joined } = await link(session);
  const rotated = await revokeDevice(joined, session.device.id);
  const state = await resolvePrism(session.prism, rotated.log);
  assert.deepEqual(state.active, [joined.device.id]);
  assert.equal(await canSign(session.prism, rotated.log, session.device.id), false);
  const late = await createLinkOffer(origin, { now: NOW });
  const intruder = await createDevice();
  const accepted = await acceptLinkRequest(origin, late.pending, await requestLink(intruder, late.offer), { now: NOW, confirmCode: await linkCode(late.offer.secret, intruder.record) });
  const after = await resolvePrism(session.prism, mergeLogs(rotated.log, accepted.session.log));
  assert.deepEqual(after.active, [joined.device.id]);
});

test('two members that revoke each other are both revoked', async () => {
  const session = await createPrism();
  const { origin, joined } = await link(session);
  const a = await revokeDevice(origin, joined.device.id);
  const b = await revokeDevice(joined, origin.device.id);
  const state = await resolvePrism(session.prism, mergeLogs(a.log, b.log));
  assert.deepEqual(state.active, []);
  assert.deepEqual(state.revoked, [origin.device.id, joined.device.id].sort());
});

test('a revoked device can no longer act for the prism at a host', async () => {
  const session = await createPrism();
  const { origin, joined } = await link(session);
  const action = await signAction(joined, 'profile/update', { name: 'x' }, { now: NOW, audience: HOST });
  assert.equal((await verifyAction(session.prism, origin.log, action, AT)).allowed, true);
  const revoked = await revokeDevice(origin, joined.device.id);
  assert.equal((await verifyAction(session.prism, revoked.log, action, AT)).allowed, false);
  const tampered = { ...action, body: { ...action.body, action: 'admin/everything' } };
  assert.equal((await verifyAction(session.prism, origin.log, tampered, AT)).allowed, false);
});

test('a host refuses an action replayed, sent to another host, or outside its time window', async () => {
  const session = await createPrism();
  const seen = new Set();
  const action = await signAction(session, 'profile/update', { name: 'x' }, { now: NOW, audience: HOST });
  assert.equal((await verifyAction(session.prism, session.log, action, { ...AT, seen })).allowed, true);
  assert.equal((await verifyAction(session.prism, session.log, action, { ...AT, seen })).reason, 'audience, replay or time window');
  assert.equal((await verifyAction(session.prism, session.log, action, { audience: 'https://other.example', now: NOW })).allowed, false);
  assert.equal((await verifyAction(session.prism, session.log, action, { ...AT, now: NOW + 60001 })).allowed, false);
  assert.equal((await verifyAction(session.prism, session.log, action, { ...AT, now: NOW - 60001 })).allowed, false);
  await assert.rejects(signAction(session, 'profile/update', {}, { now: NOW }), /audience/);
});

test('a host that requires hardware-held keys admits only attested devices', () => {
  assert.equal(hostAdmitsDevice({}, {}), true);
  assert.equal(hostAdmitsDevice({ requiresHardwareKey: true }, {}), false);
  assert.equal(hostAdmitsDevice({ requiresHardwareKey: true }, { attestedHardwareKey: 'yes' }), false);
  assert.equal(hostAdmitsDevice({ requiresHardwareKey: true }, { attestedHardwareKey: true }), true);
});

test('log merge is commutative, associative and idempotent', async () => {
  const session = await createPrism();
  const a = (await link(session)).origin;
  const b = (await link(session)).origin;
  const other = (await resolvePrism(a.prism, a.log)).active.find(d => d !== session.device.id);
  const c = await revokeDevice(a, other);
  assert.equal(await logRoot(mergeLogs(a.log, b.log)), await logRoot(mergeLogs(b.log, a.log)));
  assert.equal(await logRoot(mergeLogs(mergeLogs(a.log, b.log), c.log)), await logRoot(mergeLogs(a.log, mergeLogs(b.log, c.log))));
  assert.equal(await logRoot(mergeLogs(a.log, a.log)), await logRoot(a.log));
  assert.equal(await logRoot(await addRecord(a.log, [...a.log.values()][0])), await logRoot(a.log));
});

test('one identity is a private boundary; two make it shared; publishing makes it public', async () => {
  const [p, q, r] = await Promise.all([createPrism(), createPrism(), createPrism()]);
  assert.equal(describeBoundary({ members: [p.prism] }).visibility, 'private');
  assert.equal(describeBoundary({ members: [p.prism, p.prism] }).visibility, 'private');
  const shared = describeBoundary({ members: [q.prism, p.prism] });
  assert.equal(shared.visibility, 'shared');
  assert.deepEqual(shared.members, [p.prism, q.prism].sort());
  assert.equal(boundaryVisibleTo(shared, q.prism), true);
  assert.equal(boundaryVisibleTo(shared, r.prism), false);
  assert.equal(describeBoundary({ members: [p.prism], published: true }).visibility, 'public');
  assert.equal(boundaryVisibleTo(describeBoundary({ members: [p.prism], published: true }), r.prism), true);
  assert.throws(() => describeBoundary({ members: [] }), PrismIdError);
});

test('after linking, devices sync over the substrate bus on a topic only they can derive', async () => {
  const bus = createMemoryBus();
  const session = await createPrism();
  const { origin, joined } = await link(session);
  let phone = joined;
  const topic = await syncTopic(origin);
  assert.equal(topic, await syncTopic(phone));
  assert.notEqual(topic, await syncTopic(await createPrism()));
  bus.subscribe(topic, async bytes => { phone = await receiveSync(phone, bytes); });
  const third = await link(origin);
  await publishSync(third.origin, bus);
  const state = await resolvePrism(session.prism, phone.log);
  assert.equal(state.active.length, 3);
  assert.ok(state.active.includes(third.joined.device.id));
  // A message sealed for another prism does not open, even under the same key bytes.
  const stranger = await createPrism();
  const forged = { ...stranger, keyring: new Map([[session.prism, phone.keyring.get(session.prism)]]) };
  const bytes = await capture(bus, forged, { keyId: session.prism });
  await assert.rejects(receiveSync(phone, bytes), { name: 'OperationError' });
});

test('oversized logs and sync messages are refused before any signature work', async () => {
  const session = await createPrism();
  const [genesis] = session.log.values();
  await assert.rejects(logFromRecords(Array(MAX_LOG_RECORDS + 1).fill(genesis)), /exceeds/);
  await assert.rejects(receiveSync(session, new Uint8Array(MAX_SYNC_BYTES + 1)), /exceeds/);
});

test('the rendezvous topic depends only on the out-of-band secret', async () => {
  const session = await createPrism();
  const one = await createLinkOffer(session, { now: NOW });
  const two = await createLinkOffer(session, { now: NOW });
  assert.equal(await rendezvousTopic(one.offer.secret), await rendezvousTopic(one.offer.secret));
  assert.notEqual(await rendezvousTopic(one.offer.secret), await rendezvousTopic(two.offer.secret));
});

// ---------------------------------------------------------------- closing the residual gaps

async function syncAll(bus, from, ...to) {
  const bytes = await capture(bus, from);
  return Promise.all(to.map(s => receiveSync(s, bytes)));
}

test('R6: wraps to a device that advertises ML-KEM are hybrid, and a classical wrap to it is refused', async () => {
  const session = await createPrism();
  const { uri, pending } = await createLinkOffer(session, { now: NOW });
  const offer = parseLinkUri(uri);
  const device = await createDevice();
  const accepted = await acceptLinkRequest(session, pending, await requestLink(device, offer), { now: NOW, confirmCode: await linkCode(offer.secret, device.record) });
  if (await postQuantumAvailable()) {
    assert.equal(typeof device.record.kem, 'string');
    assert.equal(typeof accepted.response.wrap.kem, 'string');
    const downgraded = { ...accepted.response, wrap: { ...accepted.response.wrap, kem: undefined } };
    delete downgraded.wrap.kem;
    await assert.rejects(completeLink(device, offer, downgraded), /must be hybrid/);
  } else {
    assert.equal(device.record.kem, undefined);
    assert.equal(accepted.response.wrap.kem, undefined);
  }
  assert.ok((await completeLink(device, offer, accepted.response)).keyring.size > 0);
});

test('R5: sealed content is padded to power-of-two buckets', async () => {
  for (const [n, bucket] of [[0, 1024], [1023, 1024], [1024, 2048], [5000, 8192]]) {
    const padded = padToBucket(new Uint8Array(n).fill(7));
    assert.equal(padded.length, bucket);
    assert.equal(unpad(padded).length, n);
  }
  assert.throws(() => unpad(new Uint8Array(16)), /malformed padding/);
  const session = await createPrism();
  const small = await sealPrivate(session, { a: 1 });
  const larger = await sealPrivate(session, { a: 'x'.repeat(900) });
  assert.equal(small.sealed.ciphertext.length, larger.sealed.ciphertext.length);
});

test('R1: a hardened device holds only non-extractable boundary keys and cannot hand them on', async () => {
  const session = await createPrism();
  const { origin, joined } = await link(session);
  const before = await sealPrivate(origin, { kept: true });
  const hard = await hardenSession(joined);
  for (const entry of hard.keyring.values()) {
    assert.equal(entry.raw, null);
    assert.equal(entry.seal.extractable, false);
    assert.equal(entry.topic.extractable, false);
  }
  assert.deepEqual(await openPrivate(hard, before.sealed), { kept: true });
  assert.equal(await syncTopic(hard), await syncTopic(origin));
  await assert.rejects(createLinkOffer(hard, { now: NOW }), /hardened device cannot link a member/);
  await assert.rejects(createRecovery(hard, { threshold: 1, guardians: [{ paper: true }] }), /hardened device cannot set up recovery/);
  // It can still link delegates and revoke, which rotates the key without keeping the new key's bytes.
  await link(hard, { role: 'delegate', scope: ['telemetry/write'] });
  const rotated = await revokeDevice(hard, origin.device.id);
  const { keyId, entry } = await currentBoundary(rotated);
  assert.notEqual(keyId, session.prism);
  assert.equal(entry.raw, null);
});

test('R4: Shamir shares recombine only at the threshold', () => {
  const secret = new TextEncoder().encode('prism recovery secret');
  const shares = splitSecret(secret, 3, 5);
  assert.deepEqual(combineShares([shares[4], shares[0], shares[2]]), secret);
  assert.notDeepEqual(combineShares([shares[0], shares[1]]), secret);
  assert.throws(() => splitSecret(secret, 0, 3), /threshold/);
  assert.throws(() => splitSecret(secret, 4, 3), /threshold/);
});

async function withRecovery(guardianCount = 3, threshold = 2) {
  const session = await createPrism();
  const guardians = [];
  for (let i = 0; i < guardianCount - 1; i++) guardians.push((await createPrism()).device);
  const setup = await createRecovery(session, { threshold, guardians: [...guardians.map(g => g.record), { paper: true }] });
  return { session: setup.session, guardians, shares: setup.shares, recovery: setup.recovery };
}

test('R4: after losing every device, guardians release shares and the prism is recovered on a new device', async () => {
  const { session, guardians, shares, recovery } = await withRecovery();
  const before = await sealPrivate(session, { diary: 'kept' });
  const phone = await link(session);
  const state = await resolvePrism(session.prism, phone.origin.log);
  assert.equal(state.recovery, recovery);
  assert.equal(state.roles[recovery], 'recovery');
  // Everything is lost. A new device asks two guardians; each compares the code shown on it, then releases.
  const fresh = await createDevice({ deviceClass: 'mobile', protection: 'platform' });
  const code = await recoveryCode(session.prism, fresh.record);
  assert.match(code, /^\d{6}$/);
  const released = [await releaseShare(guardians[0], shares[0], fresh.record)];
  await assert.rejects(recoverPrism({ prism: session.prism, records: [...phone.origin.log.values()], shares: released, device: fresh }), /not enough shares/);
  released.push(shares[2]);
  const { session: recovered } = await recoverPrism({ prism: session.prism, records: [...phone.origin.log.values()], shares: released, device: fresh });
  const after = await resolvePrism(session.prism, recovered.log);
  assert.deepEqual(after.active, [fresh.id, recovery].sort());
  assert.ok(after.revoked.includes(session.device.id) && after.revoked.includes(phone.joined.device.id));
  assert.deepEqual(await openPrivate(recovered, before.sealed), { diary: 'kept' });
  assert.deepEqual(await openPrivate(recovered, (await sealPrivate(recovered, { x: 1 })).sealed), { x: 1 });
  await assert.rejects(releaseShare(guardians[1], shares[0], fresh.record), /not held by this guardian/);
});

test('R4: a thief holding a member device cannot lock the person out', async () => {
  const { session, guardians, shares, recovery } = await withRecovery();
  const stolen = (await link(session)).joined;
  let thief = await link(stolen, {}).then(x => x.origin);
  thief = await revokeDevice(thief, session.device.id);
  // A member cannot revoke or replace the recovery device.
  const triedRevoke = await revokeDevice(thief, recovery);
  assert.ok((await resolvePrism(session.prism, triedRevoke.log)).active.includes(recovery));
  await assert.rejects(createRecovery(thief, { threshold: 1, guardians: [{ paper: true }] }), /only the recovery device may replace it/);
  const fresh = await createDevice();
  const records = [...mergeLogs(session.log, triedRevoke.log).values()];
  const { session: recovered } = await recoverPrism({ prism: session.prism, records, shares: [await releaseShare(guardians[1], shares[1], fresh.record), shares[2]], device: fresh });
  const after = await resolvePrism(session.prism, recovered.log);
  assert.deepEqual(after.active, [fresh.id, recovery].sort());
  assert.ok(after.revoked.includes(stolen.device.id));
  // Later revocations the thief makes do not count, because recovery revoked the thief.
  const late = await revokeDevice({ ...thief, log: mergeLogs(thief.log, recovered.log) }, fresh.id).catch(e => e);
  assert.ok(late instanceof PrismIdError);
});

test('R4: recovery rotates itself so the recovered secret is retired', async () => {
  const { session, shares } = await withRecovery(2, 1);
  const fresh = await createDevice();
  const newGuardian = (await createPrism()).device;
  const { session: recovered, shares: newShares } = await recoverPrism({ prism: session.prism, records: [...session.log.values()], shares: [shares[1]], device: fresh,
    rotateRecovery: { threshold: 1, guardians: [newGuardian.record] } });
  const state = await resolvePrism(session.prism, recovered.log);
  assert.equal(newShares.length, 1);
  assert.equal(state.recovery, newShares[0].recovery);
  assert.notEqual(state.recovery, shares[1].recovery);
  assert.ok(state.revoked.includes(shares[1].recovery));
  assert.ok(state.active.includes(fresh.id));
});

test('R3: each host sees its own persona, unlinkable to the prism and to other hosts', async () => {
  const bus = createMemoryBus();
  const { session } = await withRecovery();
  let { origin, joined } = await link(session);
  origin = await ensurePersona(origin, HOST);
  origin = await ensurePersona(origin, 'https://other.example');
  const a = await personaFor(origin, HOST), b = await personaFor(origin, 'https://other.example');
  assert.notEqual(a.persona, b.persona);
  for (const view of [a, b]) {
    const text = JSON.stringify(view.records);
    assert.equal(text.includes(session.prism), false);
    assert.equal(text.includes(origin.device.id), false);
    assert.equal(text.includes(origin.device.record.sign.x), false);
  }
  const keysAt = async v => Object.values((await resolvePrism(v.persona, await logFromRecords(v.records))).devices).map(d => d.sign.x);
  const keysB = await keysAt(b);
  assert.equal((await keysAt(a)).some(x => keysB.includes(x)), false);
  // The host verifies a persona action with only the persona log.
  const action = await signPersonaAction(origin, HOST, 'profile/update', { name: 'x' }, { now: NOW });
  assert.equal((await verifyAction(a.persona, await logFromRecords(a.records), action, AT)).allowed, true);
  assert.equal((await verifyAction(b.persona, await logFromRecords(b.records), action, AT)).allowed, false);
  // The second device asks to join the persona; the first binds it on the next sync.
  [joined] = await syncAll(bus, origin, joined);
  joined = await ensurePersona(joined, HOST);
  [origin] = await syncAll(bus, joined, origin);
  [joined] = await syncAll(bus, origin, joined);
  const fromPhone = await signPersonaAction(joined, HOST, 'profile/update', { name: 'y' }, { now: NOW });
  const view = await personaFor(origin, HOST);
  assert.equal((await verifyAction(view.persona, await logFromRecords(view.records), fromPhone, AT)).allowed, true);
  // Revoking the phone in the prism revokes its persona key at the host too.
  origin = await revokeDevice(origin, joined.device.id);
  const afterRevoke = await personaFor(origin, HOST);
  assert.equal((await verifyAction(afterRevoke.persona, await logFromRecords(afterRevoke.records), fromPhone, AT)).allowed, false);
});

test('R3 + R4: a recovered prism keeps its persona at each host', async () => {
  const { session, guardians, shares } = await withRecovery();
  const withPersona = await ensurePersona(session, HOST);
  const atHost = await personaFor(withPersona, HOST);
  const fresh = await createDevice();
  const { session: recovered } = await recoverPrism({ prism: session.prism, records: [...withPersona.log.values()], device: fresh,
    shares: [await releaseShare(guardians[0], shares[0], fresh.record), shares[2]], personas: { [atHost.persona]: atHost.records } });
  const again = await personaFor(recovered, HOST);
  assert.equal(again.persona, atHost.persona);
  const action = await signPersonaAction(recovered, HOST, 'profile/update', {}, { now: NOW });
  const log = await logFromRecords(again.records);
  assert.equal((await verifyAction(again.persona, log, action, AT)).allowed, true);
  const old = await signPersonaAction(withPersona, HOST, 'profile/update', {}, { now: NOW });
  assert.equal((await verifyAction(again.persona, log, old, AT)).allowed, false);
});

test('R7: a host admits a hardware-requiring device only on an attestation bound to its own key', async () => {
  const device = await createDevice({ deviceClass: 'mobile', protection: 'platform' });
  const other = await createDevice();
  const verifiers = { test: async (evidence) => ({ hardware: evidence.hardware, key: evidence.key }) };
  const policy = { requiresHardwareKey: true };
  assert.equal(await admitDevice({}, device.record), true);
  assert.equal(await admitDevice(policy, device.record), false);
  assert.equal(await admitDevice(policy, device.record, { format: 'unknown' }, verifiers), false);
  assert.equal(await admitDevice(policy, device.record, { format: 'test', hardware: true, key: other.record.sign }, verifiers), false);
  assert.equal(await admitDevice(policy, device.record, { format: 'test', hardware: false, key: device.record.sign }, verifiers), false);
  assert.equal(await admitDevice(policy, device.record, { format: 'test', hardware: true, key: device.record.sign }, verifiers), true);
});
