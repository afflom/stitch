import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createPrism, createDevice, resolvePrism, canSign, createLinkOffer, parseLinkUri, requestLink, acceptLinkRequest, completeLink,
  linkCode, mergeLogs, createMemoryBus, signAction, verifyAction, createRecovery, recoverPrism, admitRecords, publishLog, heardLog
} from '../src/prism-id.js';

const NOW = 1_800_000_000_000;
const AT = { audience: 'https://foundry.uor.foundation', now: NOW };

/** Link a device the way a person does: scan, compare the six-digit code on both screens, confirm. */
async function link(session) {
  const { uri, pending } = await createLinkOffer(session, { now: NOW });
  const offer = parseLinkUri(uri);
  const joining = await createDevice();
  const request = await requestLink(joining, offer);
  const accepted = await acceptLinkRequest(session, pending, request, { now: NOW + 1000, confirmCode: await linkCode(offer.secret, joining.record) });
  return { origin: accepted.session, joined: await completeLink(joining, offer, accepted.response) };
}

async function withRecovery() {
  const setup = await createRecovery(await createPrism(), { threshold: 1, guardians: [{ paper: true }] });
  return { session: setup.session, shares: setup.shares };
}

/** The frame's kit: one paper share of the recovery device, and the log as it was when the kit was made. */
async function usedKit() {
  const { session, shares } = await withRecovery();
  const phone = await link(session);
  const kit = { share: shares[0], records: [...phone.origin.log.values()] };
  const fresh = await createDevice();
  const real = await recoverPrism({ prism: session.prism, records: kit.records, shares: [kit.share], device: fresh, rotateRecovery: { threshold: 1, guardians: [{ paper: true }] } });
  return { prism: session.prism, kit, real, fresh, phone };
}

test('R4: an old recovery kit replayed against its old log binds and revokes nothing', async () => {
  const { prism, kit, real, fresh } = await usedKit();
  const replayer = await createDevice();
  const replay = await recoverPrism({ prism, records: kit.records, shares: [kit.share], device: replayer });
  const merged = mergeLogs(real.session.log, replay.session.log);
  const state = await resolvePrism(prism, merged);
  assert.deepEqual(state.active, [fresh.id, real.shares[0].recovery].sort());
  assert.deepEqual(state.retired, [kit.share.recovery]);
  assert.equal(await canSign(prism, merged, replayer.id), false);
  assert.equal(await canSign(prism, merged, fresh.id), true);
  const action = await signAction(replay.session, 'post', { text: 'not the person' }, AT);
  assert.equal((await verifyAction(prism, merged, action, AT)).allowed, false);
  assert.equal((await verifyAction(prism, merged, await signAction(real.session, 'post', { text: 'the person' }, AT), AT)).allowed, true);
});

test('R4: a replay that also retires the old recovery forks the log: hosts act for neither side, devices refuse the fork', async () => {
  const { prism, kit, real, fresh } = await usedKit();
  const replayer = await createDevice();
  const replay = await recoverPrism({ prism, records: kit.records, shares: [kit.share], device: replayer, rotateRecovery: { threshold: 1, guardians: [{ paper: true }] } });
  // Each side alone resolves; together they are a fork.
  assert.ok((await resolvePrism(prism, replay.session.log)).active.includes(replayer.id));
  const merged = mergeLogs(real.session.log, replay.session.log);
  await assert.rejects(resolvePrism(prism, merged), /fork/);
  const action = await signAction(replay.session, 'post', { text: 'not the person' }, AT);
  await assert.rejects(verifyAction(prism, merged, action, AT), /fork/);
  // The person's device holds the real retirement and never admits the replayed one.
  const held = await admitRecords(prism, real.session.log, replay.session.log);
  const state = await resolvePrism(prism, held);
  assert.deepEqual(state.active, [fresh.id, real.shares[0].recovery].sort());
  const bus = createMemoryBus();
  await publishLog(replay.session, bus);
  await publishLog(real.session, bus);
  assert.equal(await canSign(prism, await heardLog(prism, real.session.log, bus, { own: true }), fresh.id), true);
  await assert.rejects(resolvePrism(prism, await heardLog(prism, new Map(real.session.log), bus)), /fork/);
});

test('R4: recovering again with the newer kit leaves the retired recovery device alone', async () => {
  const { prism, real } = await usedKit();
  const again = await createDevice();
  const second = await recoverPrism({ prism, records: [...real.session.log.values()], shares: real.shares, device: again, rotateRecovery: { threshold: 1, guardians: [{ paper: true }] } });
  const state = await resolvePrism(prism, second.session.log);
  assert.deepEqual(state.active, [again.id, second.shares[0].recovery].sort());
  assert.equal(state.retired.length, 2);
});

