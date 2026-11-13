import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createPrism, createDevice, resolvePrism, revokeDevice, sealPrivate, openPrivate, PrismIdError,
  createRecovery, openRecovery, recoverOnto, encodeCode, decodeCode, recoveryLocator, RECOVERY_KIND
} from '../src/prism-id.js';

const NOW = 1_800_000_000_000;
const refused = code => error => error instanceof PrismIdError && error.code === code;

test('a recovery code is 56 Crockford characters that survive retyping', async () => {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const code = await encodeCode(seed);
  assert.match(code, /^([0-9A-HJKMNP-TV-Z]{4} ){13}[0-9A-HJKMNP-TV-Z]{4}$/);
  assert.deepEqual(await decodeCode(code), seed);
  assert.deepEqual(await decodeCode(code.toLowerCase().replace(/ /g, '-').replace(/1/g, 'l').replace(/0/g, 'o')), seed);
  const typo = code.slice(0, 5) + (code[5] === 'A' ? 'B' : 'A') + code.slice(6);
  await assert.rejects(decodeCode(typo), refused('code'));
  await assert.rejects(decodeCode('0000 0000'), refused('code'));
});

test('a lost device: the code links a new device to the same prism, with its private boundary', async () => {
  const lost = await createPrism();
  const secret = await sealPrivate(lost, { note: 'kept through the loss' });
  const made = await createRecovery(lost, { now: NOW });
  assert.equal(made.escrow.kind, RECOVERY_KIND.escrow);
  assert.equal(made.escrow.locator, await recoveryLocator(await decodeCode(made.code)));
  assert.ok(!JSON.stringify(made.escrow).includes(made.code.replace(/ /g, '')));
  assert.deepEqual((await resolvePrism(lost.prism, made.session.log)).active, [lost.device.id, made.device].sort());

  const fresh = await createDevice();
  const joined = await recoverOnto(made.code, made.escrow, fresh, { now: NOW + 1000 });
  assert.equal(joined.prism, lost.prism);
  const state = await resolvePrism(lost.prism, joined.log);
  assert.ok(state.active.includes(fresh.id));
  assert.deepEqual(await openPrivate(joined, secret.sealed), { note: 'kept through the loss' });

  // The new device takes the lost one out; the prism carries on.
  const cleaned = await revokeDevice(joined, lost.device.id);
  const after = await resolvePrism(lost.prism, cleaned.log);
  assert.ok(!after.active.includes(lost.device.id));
  assert.ok(after.active.includes(fresh.id));
});

test('an escrow opens only with its own code', async () => {
  const session = await createPrism();
  const one = await createRecovery(session, { now: NOW });
  const two = await createRecovery(one.session, { now: NOW });
  await assert.rejects(openRecovery(one.code, two.escrow), refused('escrow'));
  const tampered = { ...one.escrow, ciphertext: one.escrow.ciphertext.slice(0, -4) + 'AAAA' };
  await assert.rejects(openRecovery(one.code, tampered), refused('escrow'));
  assert.equal((await openRecovery(one.code, one.escrow)).prism, session.prism);
});

test('a revoked recovery code links nothing', async () => {
  const session = await createPrism();
  const made = await createRecovery(session, { now: NOW });
  const revoked = await revokeDevice(made.session, made.device);
  await assert.rejects(recoverOnto(made.code, made.escrow, await createDevice(), { now: NOW, log: revoked.log }), refused('unauthorized'));
});
