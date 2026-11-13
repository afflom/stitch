import { test, expect } from './fixtures.mjs';
import { mkdirSync } from 'node:fs';
const screenshots = new URL('../../verification-output/browser/reader/', import.meta.url).pathname;

async function expectResult(page, state) {
  await expect(page.locator('#exampleResult')).toHaveAttribute('data-state', state);
}

test('reader explorer recovers, withholds and refuses exact bytes without joining the network', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/#reader-test-mesh');
  await expectResult(page, 'recovered');
  await expect(page.locator('#recoveredText')).toHaveText('Keep the bytes. Change the peers.');
  const before = await page.evaluate(() => ({ hash: location.hash, history: history.length }));
  await page.getByRole('button', { name: 'Try losing a fragment ↓' }).click();
  await expect(page.locator('#protocolExplorer')).toBeFocused();
  await page.locator('#presetone').click(); await expectResult(page, 'recovered');
  await expect(page.locator('#recoveryCount')).toHaveText('2 / 3');
  await page.locator('#presettwo').click(); await expectResult(page, 'insufficient');
  await expect(page.locator('#recoveredText')).toHaveText('No recovered output accepted.');
  await page.locator('#presettamper').click(); await expectResult(page, 'refused');
  await expect(page.locator('#exampleResultDetail')).toContainText('FragmentDigestMismatch');
  await page.locator('#available0').uncheck(); await expectResult(page, 'recovered');
  await page.locator('#presetcomplete').click(); await expectResult(page, 'recovered');
  await page.locator('#exampleInput').fill('Updated object 🧵');
  await page.locator('#encodeExample').click(); await expectResult(page, 'recovered');
  await expect(page.locator('#recoveredText')).toHaveText('Updated object 🧵');
  await page.locator('#exampleInput').fill('🧵'.repeat(65));
  await page.locator('#encodeExample').click();
  await expect(page.locator('#exampleInputStatus')).toContainText('at most 256 UTF-8 bytes');
  await expect(page.locator('#exampleControls')).toBeHidden();
  await page.locator('#exampleInput').fill('');
  await page.locator('#encodeExample').click(); await expectResult(page, 'recovered');
  await expect(page.locator('#recoveredText')).toHaveText('(empty object)');
  for (const id of ['corrupt0', 'corrupt1', 'corrupt2']) await expect(page.locator(`#${id}`)).toBeDisabled();
  await page.getByRole('button', { name: 'Open console ↗' }).click();
  await expect(page.locator('#operatorConsole')).toBeFocused();
  expect(await page.evaluate(() => ({ hash: location.hash, history: history.length }))).toEqual(before);
  await expect(page.locator('#allowMeshSignalingInput')).not.toBeChecked();
  await expect(page.locator('#allowPublicRelayInput')).not.toBeChecked();
  await expect(page.locator('#peerCountLabel')).toHaveText('0');
});

test('interrupted encoding and repeated scenarios cannot publish stale results or strand busy state', async ({ page }) => {
  await page.goto('/'); await expectResult(page, 'recovered');
  await page.evaluate(() => {
    const original = crypto.subtle.digest.bind(crypto.subtle);
    let hold = true;
    crypto.subtle.digest = async (...args) => {
      if (hold) { hold = false; await new Promise(resolve => { window.releaseExampleDigest = resolve; }); }
      return original(...args);
    };
  });
  await page.locator('#exampleInput').fill('First in flight');
  await page.locator('#encodeExample').click();
  await expect(page.locator('#exampleControls')).toBeHidden();
  await expect(page.locator('#encodeExample')).toBeDisabled();
  // Synthetic events also exercise busy guards; users cannot click hidden controls.
  await page.evaluate(() => document.getElementById('presettamper').click());
  await page.locator('#exampleInput').fill('The latest input');
  await page.evaluate(() => document.getElementById('exampleForm').dispatchEvent(new Event('submit', { cancelable: true })));
  await expectResult(page, 'recovered');
  await expect(page.locator('#recoveredText')).toHaveText('The latest input');
  await page.evaluate(() => window.releaseExampleDigest());
  await expect(page.locator('#encodeExample')).toBeEnabled();
  await expect(page.locator('#exampleInputStatus')).not.toContainText('Encoding');
  await expect(page.locator('#recoveredText')).toHaveText('The latest input');
  await page.evaluate(() => {
    for (let i = 0; i < 5; i++) {
      document.getElementById('presettamper').click();
      document.getElementById('presettwo').click();
      document.getElementById('presetone').click();
    }
  });
  await expectResult(page, 'recovered');
  await expect(page.locator('#recoveryCount')).toHaveText('2 / 3');
});

for (const viewport of [{ name: 'desktop', width: 1440, height: 1000 }, { name: 'mobile', width: 390, height: 844 }]) {
  test(`reader layout stays within ${viewport.name} viewport and supplies accessible navigation`, async ({ page }) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.goto('/'); await expectResult(page, 'recovered');
    await expect(page.locator('.facet-card')).not.toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    mkdirSync(screenshots, { recursive: true });
    await page.screenshot({ path: `${screenshots}${viewport.name}-hero.png` });
    await page.locator('#exampleForm').scrollIntoViewIfNeeded();
    await page.locator('.example-box').screenshot({ path: `${screenshots}${viewport.name}-explorer.png` });
    await page.getByRole('button', { name: 'How Stitch works' }).focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('#protocolMap')).toBeFocused();
    await page.getByRole('button', { name: 'Open console ↗' }).click();
    await page.locator('#operatorJourneyNav button[aria-controls="objectsPanel"]').click();
    await page.locator('#dbPutBtn').click();
    await expect(page.locator('#liveDbBody')).toContainText('sha256:');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await expect(page.locator('#allowMeshSignalingInput')).not.toBeChecked();
  });
}
