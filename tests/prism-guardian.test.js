import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createPrism, createDevice, resolvePrism, canSign, createRecovery, replaceRecovery, releaseShare, recoverPrism, recoveryCode
} from '../src/prism-id.js';

const PAPER = { threshold: 1, guardians: [{ paper: true }] };

/** The frame's id: one device, a kit of one paper share. A guardian is a device of another person's prism. */
async function guarded() {
  const made = await createRecovery(await createPrism(), PAPER);
  const guardian = (await createPrism()).device;
  const replaced = await replaceRecovery(made.session, [made.shares[0]], { threshold: 2, guardians: [{ paper: true }, guardian.record] });
  return { made, guardian, replaced, prism: made.session.prism };
}

test('R4: a guardian joins a paper kit without a recovery, and the member never holds the recovery secret', async () => {
  const { made, guardian, replaced, prism } = await guarded();
  const state = await resolvePrism(prism, replaced.session.log);
  assert.deepEqual(state.active, [made.session.device.id, replaced.recovery].sort());
  assert.deepEqual(state.retired, [made.shares[0].recovery]);
  assert.equal(state.recovery, replaced.recovery);
  const [paper, held] = replaced.shares;
  assert.equal(paper.guardian, 'paper');
  assert.equal(held.guardian, guardian.id);
  assert.equal(paper.threshold, 2);
  assert.ok(!('share' in held), 'the guardian share is wrapped to the guardian only');
  assert.equal(await canSign(prism, replaced.session.log, made.session.device.id), true);
  // The member's keyring took up the rotation the old recovery device made when it retired.
  assert.ok(replaced.session.keyring.has(state.boundary.keyId));
});

test('R4: the paper share alone no longer recovers; with the share a guardian released, it does', async () => {
  const { replaced, guardian, prism } = await guarded();
  const [paper, held] = replaced.shares;
  const records = [...replaced.session.log.values()];
  await assert.rejects(recoverPrism({ prism, records, shares: [paper], device: await createDevice() }), /not enough shares/);
  const fresh = await createDevice();
  assert.match(await recoveryCode(prism, fresh.record), /^\d{6}$/);
  const released = await releaseShare(guardian, held, fresh.record);
  const recovered = await recoverPrism({ prism, records, shares: [paper, released], device: fresh, rotateRecovery: PAPER });
  const state = await resolvePrism(prism, recovered.session.log);
  assert.deepEqual(state.active, [fresh.id, recovered.shares[0].recovery].sort());
  // The guardian's share opens only on the device it was released to.
  await assert.rejects(recoverPrism({ prism, records, shares: [paper, released], device: await createDevice() }));
});

test('R4: a guardian share is refused to a guardian it was not made for, and the old paper kit is retired', async () => {
  const { made, replaced, prism } = await guarded();
  const stranger = (await createPrism()).device;
  await assert.rejects(releaseShare(stranger, replaced.shares[1], (await createDevice()).record), /not held by this guardian/);
  const records = [...replaced.session.log.values()];
  await assert.rejects(recoverPrism({ prism, records, shares: [made.shares[0]], device: await createDevice() }), /not enough shares/);
});
