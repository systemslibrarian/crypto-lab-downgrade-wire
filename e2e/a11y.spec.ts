import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the skip link focused; the
 * step-by-step guide opened through its summary; the SHIPPED configuration run
 * first (bound and unstripped, which is the only route on the page to the
 * "identical" MAC-diff badges); the hybrid group struck by clicking its ✕ and
 * run bound, so the defense holds and every differing byte is marked; the same
 * strip run unbound, which is the canonical downgrade; "PQC required" refusing
 * the downgraded suite and both groups struck to leave nothing to offer, which
 * are the two amber verdicts nothing else on the page reaches; the offer reset;
 * the compare rail under both server policies; the one-click preset; the Copy
 * link button's transient flashed label; the policy panel's two cards; all four
 * sentinel checkbox combinations, including the DETECTED state the lab ships
 * with; and both fail-open retry policies. Every one of those states is scanned,
 * in both themes, at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no `<details>` is
 * force-opened, why the lab's defaults are asserted rather than assumed, and why
 * `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
    expectBaselineNotStale();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
    expectBaselineNotStale();
  });
}
