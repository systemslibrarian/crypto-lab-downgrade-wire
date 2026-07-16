import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Drive every panel so the dynamic result regions — both verdict states (the
 * green DEFENSE-HELD chip and the red DOWNGRADE alarm), the policy cards, the
 * missed-sentinel alarm, the fail-open chips, and the MAC-diff table — are all
 * present in the DOM when axe scans.
 */
async function prepare(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}`,
  });

  // The strip: one-click canonical downgrade (unbound → alarm + aha).
  await page.locator('#strip-play').click();
  await expect(page.locator('#strip .chip-alarm').first()).toBeVisible();
  // Side-by-side compare rail (both verdict states rendered at once).
  await page.locator('#strip-compare').click();
  await expect(page.locator('#strip .compare-card')).toHaveCount(2);
  // Bound run of the same strip → DEFENSE HELD chip + the green aha-ok note.
  await page.locator('#binding-bound').check();
  await page.locator('#strip-run').click();
  await expect(page.locator('#strip .aha-ok')).toBeVisible();

  // Policy side-by-side.
  await page.locator('#policy-run').click();
  await expect(page.locator('#policy .policy-card')).toHaveCount(2);

  // Sentinel: force the "missed" alarm state (present but unchecked).
  await page.getByLabel('Client checks the sentinel').uncheck();
  await expect(page.locator('#sentinel .chip-alarm')).toBeVisible();

  // Fail-open: two rounds ending in the downgrade alarm.
  await page.locator('#failopen-run').click();
  await expect(page.locator('#failopen .attempt')).toHaveCount(2);

  // Reveal every collapsed <details> (the MAC-diff evidence) for the scan.
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => ((d as HTMLDetailsElement).open = true));
  });
  await page.waitForTimeout(400);
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(
    violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    })),
  ).toEqual([]);
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.');
  await prepare(page);
  await scan(page);
});

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await prepare(page);
  await scan(page);
});
