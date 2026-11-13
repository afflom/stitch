import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalJson, kappa, isKappa, createPrism, createDevice, resolvePrism, canSign, revokeDevice,
  createLinkOffer, parseLinkUri, requestLink, acceptLinkRequest, completeLink, rendezvousTopic,
  mergeLogs, logRoot, addRecord, describeBoundary, boundaryVisibleTo, sealPrivate, openPrivate,
  syncTopic, publishSync, receiveSync, createMemoryBus, PrismIdError, KIND
} from '../src/prism-id.js';

const NOW = 1_800_000_000_000;

async function link(session, { now = NOW } = {}) {
  const { uri, pending } = await createLinkOffer(session, { now });
  const offer = parseLinkUri(uri);
  const device = await createDevice();
  const request = await requestLink(device, offer);
  const accepted = await acceptLinkRequest(session, pending, request, { now: now + 1000 });
  const joined = await completeLink(device, offer, accepted.response);
  return { origin: accepted.session, joined, offer, pending, request };
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

test('a prism comes into being without any account; its id is the kappa of its genesis', async () => {
  const session = await createPrism();
  assert.ok(isKappa(session.prism));
  const [genesis] = session.log.values();
  assert.equal(genesis.body.kind, KIND.genesis);
  assert.equal(await kappa(genesis.body), session.prism);
  const state = await resolvePrism(session.prism, session.log);
  assert.deepEqual(state.active, [session.device.id]);
  assert.equal(await canSign(session.prism, session.log, session.device.id), true);
  assert.notEqual((await createPrism()).prism, session.prism);
});

test('device keys are non-extractable', async () => {
  const device = await createDevice();
  assert.equal(device.signingKey.extractable, false);
  assert.equal(device.agreementKey.extractable, false);
  assert.equal(device.id, await kappa(device.record));
});

test('an out-of-band offer links a second device and hands it the private boundary', async () => {
  const session = await createPrism();
  const secret = await sealPrivate(session, { note: 'only my devices' });
  const { origin, joined } = await link(session);
  assert.equal(joined.prism, session.prism);
  const state = await resolvePrism(session.prism, joined.log);
  assert.deepEqual(state.active, [session.device.id, joined.device.id].sort());
  assert.deepEqual(await openPrivate(joined, secret.sealed), { note: 'only my devices' });
  assert.equal(await logRoot(origin.log), await logRoot(joined.log));
  assert.equal(await canSign(joined.prism, joined.log, joined.device.id), true);
});

test('the offer is single use, expires, and refuses a request without the secret', async () => {
  const session = await createPrism();
  const { uri, pending } = await createLinkOffer(session, { now: NOW, ttl: 1000 });
  const offer = parseLinkUri(uri);
  const device = await createDevice();
  const request = await requestLink(device, offer);
  await assert.rejects(acceptLinkRequest(session, pending, request, { now: NOW + 1000 }), /link request refused/);
  const forged = await requestLink(device, { ...offer, secret: 'A'.repeat(43) });
  await assert.rejects(acceptLinkRequest(session, pending, forged, { now: NOW }), /link request refused/);
  await acceptLinkRequest(session, pending, request, { now: NOW });
  await assert.rejects(acceptLinkRequest(session, pending, request, { now: NOW }), /link request refused/);
  const stranger = await createPrism();
  await assert.rejects(completeLink(await createDevice(), { ...offer, prism: stranger.prism }, { kind: KIND.response, prism: stranger.prism, records: [...stranger.log.values()] }), /did not bind this device/);
});

test('an unlinked device cannot bind devices or revoke', async () => {
  const session = await createPrism();
  const outsider = await createPrism();
  const forged = { ...session, device: outsider.device };
  await assert.rejects(revokeDevice(forged, session.device.id), /may not sign/);
  await assert.rejects(createLinkOffer(forged, { now: NOW }), /may not sign/);
  // A bind signed by a foreign device and injected into the log is ignored.
  const { joined } = await link(outsider);
  const injected = mergeLogs(session.log, joined.log);
  const state = await resolvePrism(session.prism, injected);
  assert.deepEqual(state.active, [session.device.id]);
});

test('revocation removes a device; rotation keeps the devices the revoker knew', async () => {
  const session = await createPrism();
  const { origin, joined } = await link(session);
  const rotated = await revokeDevice(joined, session.device.id);
  const state = await resolvePrism(session.prism, rotated.log);
  assert.deepEqual(state.active, [joined.device.id]);
  assert.deepEqual(state.revoked, [session.device.id]);
  assert.equal(await canSign(session.prism, rotated.log, session.device.id), false);
  // The revoked device later binds a new device; revocation wins.
  const late = await createLinkOffer(origin, { now: NOW });
  const intruder = await createDevice();
  const accepted = await acceptLinkRequest(origin, late.pending, await requestLink(intruder, late.offer), { now: NOW });
  const merged = mergeLogs(rotated.log, accepted.session.log);
  const after = await resolvePrism(session.prism, merged);
  assert.deepEqual(after.active, [joined.device.id]);
});

test('log merge is commutative, associative and idempotent', async () => {
  const session = await createPrism();
  const a = (await link(session)).origin;
  const b = (await link(session)).origin;
  const c = await revokeDevice(a, [...(await resolvePrism(a.prism, a.log)).active].find(d => d !== session.device.id));
  const root = async log => logRoot(log);
  assert.equal(await root(mergeLogs(a.log, b.log)), await root(mergeLogs(b.log, a.log)));
  assert.equal(await root(mergeLogs(mergeLogs(a.log, b.log), c.log)), await root(mergeLogs(a.log, mergeLogs(b.log, c.log))));
  assert.equal(await root(mergeLogs(a.log, a.log)), await root(a.log));
  assert.equal(await root(await addRecord(a.log, [...a.log.values()][0])), await root(a.log));
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
  // A message sealed for another prism does not open, even under the same key.
  const stranger = await createPrism();
  const forged = { ...stranger, boundaryKey: phone.boundaryKey };
  let captured;
  bus.subscribe(await syncTopic(forged), bytes => { captured = bytes; });
  await publishSync(forged, bus);
  await assert.rejects(receiveSync(phone, captured), { name: 'OperationError' });
});

test('the rendezvous topic depends only on the out-of-band secret', async () => {
  const session = await createPrism();
  const one = await createLinkOffer(session, { now: NOW });
  const two = await createLinkOffer(session, { now: NOW });
  assert.equal(await rendezvousTopic(one.offer.secret), await rendezvousTopic(one.offer.secret));
  assert.notEqual(await rendezvousTopic(one.offer.secret), await rendezvousTopic(two.offer.secret));
});
