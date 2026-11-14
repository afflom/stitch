import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createPrism, createDevice, resolvePrism, revokeDevice, createLinkOffer, parseLinkUri, requestLink, acceptLinkRequest,
  completeLink, rendezvousTopic, linkCode, currentBoundary, syncTopic, publishSync, receiveSync, signAction, verifyAction, PrismIdError,
  createRelayBus, relayTopic
} from '../src/prism-id.js';

const HOST = 'https://foundry.uor.foundation';
const json = value => new TextEncoder().encode(JSON.stringify(value));
const parse = bytes => JSON.parse(new TextDecoder().decode(bytes));
const refused = code => error => error instanceof PrismIdError && error.code === code;
const settle = () => new Promise(resolve => setTimeout(resolve, 20));

/** An ntfy-shaped relay in memory: POST keeps a message, GET ?poll=1 lists them, a socket hears new ones. */
function fakeRelay() {
  const topics = new Map(), sockets = new Set(), posted = [];
  const lines = name => topics.get(name) ?? [];
  async function fetch(url, init = {}) {
    const { pathname } = new URL(url);
    const name = pathname.split('/')[1];
    if (init.method === 'POST') {
      posted.push({ name, body: init.body });
      topics.set(name, [...lines(name), init.body]);
      for (const socket of sockets) if (socket.name === name) socket.onmessage?.({ data: JSON.stringify({ event: 'message', message: init.body }) });
      return { ok: true, status: 200 };
    }
    const body = lines(name).map(message => JSON.stringify({ event: 'message', message })).join('\n');
    return { ok: true, status: 200, text: async () => body };
  }
  class WebSocket {
    constructor(url) { this.name = new URL(url).pathname.split('/')[1]; sockets.add(this); }
    close() { sockets.delete(this); }
  }
  return { fetch, WebSocket, posted, sockets };
}

const bus = relay => createRelayBus({ relay: 'https://relay.test', fetch: relay.fetch, WebSocket: relay.WebSocket, BroadcastChannel: null });

test('the relay sees a hashed topic and the framed bytes; another bus gets them, live and from what the relay holds', async () => {
  const relay = fakeRelay();
  const a = bus(relay), b = bus(relay);
  const topic = 'prism-sync:' + 'ab'.repeat(32);
  const live = [];
  const stop = b.subscribe(topic, bytes => live.push(parse(bytes)));
  await settle();
  assert.equal(await a.publish(topic, json({ n: 1 })), true);
  await settle();
  assert.deepEqual(live, [{ n: 1 }]);
  assert.equal(relay.posted[0].name, await relayTopic(topic));
  assert.ok(!relay.posted[0].name.includes('ab'.repeat(8)) && relay.posted[0].name.length <= 64);
  // Later, and only for this topic: what the relay still holds.
  assert.deepEqual((await b.fetch(topic)).map(parse), [{ n: 1 }]);
  assert.deepEqual(await b.fetch('prism-sync:' + 'cd'.repeat(32)), []);
  // A bus never hears itself.
  assert.deepEqual(await a.fetch(topic), []);
  stop();
  assert.equal(relay.sockets.size, 0);
  assert.throws(() => a.subscribe('not-a-topic', () => {}), TypeError);
});

test('a message larger than one relay frame arrives whole', async () => {
  const relay = fakeRelay();
  const big = new Uint8Array(40000).map((_, i) => i % 251);
  await bus(relay).publish('prism-sync:' + '01'.repeat(32), big);
  assert.ok(relay.posted.length > 1);
  const [got] = await bus(relay).fetch('prism-sync:' + '01'.repeat(32));
  assert.deepEqual(got, big);
});

test('two devices link over the relay, with the six-digit code, and then sync a removal', async () => {
  const relay = fakeRelay();
  const now = Date.now();
  // The person's first device, and the browser they want to add.
  let first = await createPrism();
  const firstBus = bus(relay), newBus = bus(relay);
  const { uri, pending } = await createLinkOffer(first, { now });
  const joining = await createDevice();

  // Out of band: the new device reads the offer (QR code or pasted text) and answers on the rendezvous topic.
  const offer = parseLinkUri(uri);
  const topic = await rendezvousTopic(offer.secret);
  const requests = [];
  const stopFirst = firstBus.subscribe(topic, bytes => requests.push(parse(bytes)));
  const responses = [];
  const stopNew = newBus.subscribe(topic, bytes => responses.push(parse(bytes)));
  await settle();
  await newBus.publish(topic, json(await requestLink(joining, offer)));
  await settle();
  assert.equal(requests.length, 1);

  // Both screens show the same code; the person confirms it on the first device.
  const code = await linkCode(offer.secret, joining.record);
  const accepted = await acceptLinkRequest(first, pending, requests[0], { now: now + 1000, confirmCode: code });
  first = accepted.session;
  await firstBus.publish(topic, json(accepted.response));
  await settle();
  const second = await completeLink(joining, offer, responses[0]);
  stopFirst(); stopNew();
  assert.equal(second.prism, first.prism);

  // The same prism id signs in from the new device.
  const signed = await signAction(second, 'prism/session/1', { app: 1 }, { now: now + 2000, audience: HOST });
  await verifyAction(second.prism, second.log, signed, { audience: HOST, now: now + 2000 });

  // The first device removes a lost device; the second hears it on the sync topic.
  const lost = await createDevice();
  const linkedLost = await createLinkOffer(first, { now });
  const lostRequest = await requestLink(lost, parseLinkUri(linkedLost.uri));
  first = (await acceptLinkRequest(first, linkedLost.pending, lostRequest, { now: now + 1000,
    confirmCode: await linkCode(parseLinkUri(linkedLost.uri).secret, lost.record) })).session;
  const { keyId: before } = await currentBoundary(first);
  first = await revokeDevice(first, lost.id);
  // After a rotation, once under the previous key too: the second device still listens there.
  await publishSync(first, firstBus);
  await publishSync(first, firstBus, { keyId: before });
  let synced = second;
  for (const bytes of await bus(relay).fetch(await syncTopic(second))) {
    try { synced = await receiveSync(synced, bytes); } catch (error) { if (!(error instanceof PrismIdError)) throw error; }
  }
  const state = await resolvePrism(synced.prism, synced.log);
  assert.ok(state.revoked.includes(lost.id));
  assert.ok(state.active.includes(joining.id));
});

test('a copied genesis with another signature cannot make the log unresolvable', async () => {
  const session = await createPrism();
  const [genesis] = session.log.values();
  const forged = { ...genesis, signature: genesis.signature.slice(0, -4) + 'AAAA' };
  const log = new Map([...session.log, ['forged', forged]]);
  assert.deepEqual((await resolvePrism(session.prism, log)).active, [session.device.id]);
  await assert.rejects(resolvePrism(session.prism, new Map([['forged', forged]])), refused('genesis'));
});
