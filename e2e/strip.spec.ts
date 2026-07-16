import { expect, test } from '@playwright/test';

// Narrative-correctness gate: for a teaching demo, the copy that appears next to
// each outcome is part of correctness. These lock the result/verdict/supporting
// text for every branch of the headline interaction — and specifically that the
// downgrade "aha" never appears once the defense has caught the strip.

test.describe('strip panel narrative correctness', () => {
  test('unbound + stripped hybrid → COMPLETED on x25519, DOWNGRADE ALARM', async ({ page }) => {
    await page.goto('.');
    await page.locator('#strip-play').click(); // strip + unbound + preferred + run
    const results = page.locator('#strip .strip-results');
    await expect(results.locator('.chip-neutral')).toContainText('Handshake COMPLETED on x25519');
    await expect(results.locator('.chip-alarm')).toContainText('DOWNGRADE — ALARM');
    await expect(results.locator('.aha')).toContainText('neither side ever learns');
  });

  test('bound + stripped hybrid → ABORTED, DEFENSE HELD, and NO downgrade aha', async ({ page }) => {
    await page.goto('.');
    await page.getByRole('button', { name: /Strip X25519MLKEM768/ }).click();
    await page.locator('#strip-run').click(); // default binding = TLS 1.3
    const results = page.locator('#strip .strip-results');
    await expect(results.locator('.chip-neutral')).toContainText('Finished MAC mismatch');
    await expect(results.locator('.chip-ok')).toContainText('DEFENSE HELD');
    await expect(results.locator('.aha-ok')).toContainText('downgrade is caught');
    // The unbound-only paragraph must be absent once the strip is detected.
    await expect(results.getByText('neither side ever learns the stronger option')).toHaveCount(0);
  });

  test('one Compare action renders both worlds side by side', async ({ page }) => {
    await page.goto('.');
    await page.locator('#strip-compare').click();
    const cards = page.locator('#strip .compare-card');
    await expect(cards).toHaveCount(2);
    await expect(cards.nth(0)).toContainText('DOWNGRADE — ALARM'); // Unbound
    await expect(cards.nth(1)).toContainText('DEFENSE HELD'); // TLS 1.3
  });

  test('deep link #scenario=strip-unbound-preferred auto-plays the downgrade', async ({ page }) => {
    await page.goto('./#scenario=strip-unbound-preferred');
    await expect(page.locator('#strip .chip-alarm')).toContainText('DOWNGRADE — ALARM');
  });
});
