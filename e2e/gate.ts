import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Four rules govern everything here, each one a correction of the gate this
 * replaces:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old gate pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag` before each of its two scans. That is not a neutral freeze:
 *     it BYPASSES this stylesheet's own `@media (prefers-reduced-motion:
 *     reduce)` block instead of exercising it, so the one defect that block
 *     could carry — cancelling an animation without restoring the end state it
 *     was animating towards — was structurally unreachable.
 *
 *     This lab gets that right twice over, and the gate now measures it rather
 *     than reading it. The CSS side is minimal and safe: the reduced-motion
 *     block contains exactly one declaration, `.flight-packet { transition:
 *     none }`, and a `transition` that never runs leaves the element at its
 *     declared `left`, which is its rest position. Nothing is left mid-flight
 *     and nothing is left transparent. The JS side is where the real work is:
 *     `playFlight()` reads `matchMedia('(prefers-reduced-motion: reduce)')`
 *     itself and takes a wholly different path — it writes the post-strip hex
 *     straight into the packet and returns, rather than stepping the packet
 *     through `at-attacker` / `snip` / `at-server` with two `await wait(...)`s.
 *     `boot` asks for the preference and ASSERTS it took effect, so the gate
 *     always drives that second path; `settle` waits for animations to drain;
 *     and `expectNotBlank` asserts nothing landed at zero opacity.
 *
 *  2. IT FORCE-OPENED EVERY `<details>` FROM SCRIPT before its scan
 *     (`d.open = true` over `querySelectorAll('details')`), so the SHUT state —
 *     which is how `.guide-details` arrives on every load, and how the MAC-diff
 *     `.expert` panel arrives after every run — was never scanned, and the open
 *     one was never reached the way a reader reaches it. Each is now opened by
 *     clicking its own `<summary>`.
 *
 *  3. IT SCANNED ONCE PER THEME, AT ONE VIEWPORT, AND THREW EVERY STATE AWAY.
 *     The old `prepare()` did drive the page — it played the downgrade, ran the
 *     compare rail, ran a bound strip, ran the policy panel, unchecked the
 *     sentinel and ran fail-open — and then scanned exactly once, at the end,
 *     with all of it piled on top of itself. Every intermediate rendering was
 *     discarded unmeasured, and several states were never built at all: the
 *     idle first paint, the packet with one entry struck, the SECURE verdict,
 *     the POLICY_DENIED verdict, the NO_CONNECTION verdict, the `.vb-ok`
 *     "identical" badges (reachable only from a CLEAN bound run, which it never
 *     did), the sentinel's shipped DETECTED state, the fail-closed branch, the
 *     reset, and the entire 380px column. This drive scans after every single
 *     step, in both themes, at 1280px and 380px.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. Note especially that
 *     every surface this lab uses to state an outcome is a `color-mix()`, which
 *     axe files under `incomplete` — so the old violations-only assertion had
 *     measured the contrast of not one chip, badge or highlighted byte.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This lab does not currently have an element in that shape: it declares no
 * `@keyframes` at all, its one motion is a `left` transition on
 * `.flight-packet` whose rest position is also its declared position, and the
 * only `opacity` on the page is `.cl-hero-sub` at `.85` and `.pkt-struck` at an
 * explicit `1`. The assertion runs in every state anyway, because "no element
 * is in that shape" is a property of the current stylesheet and not of the
 * page, and because the cheapest place to catch the first one is here.
 *
 * `aria-hidden` subtrees are excluded. The cost of that exclusion is stated
 * plainly: text removed from the accessibility tree AND painted at zero opacity
 * is not checked here — which on this page means the `.flight` widget, whose
 * text is instead measured by hand (see the header of `contrast.ts`).
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created.
 *
 * A renderer that throws halfway through leaves an earlier state on screen, and
 * a gate that scans that state reports green for a page that is broken. That
 * matters more than usual here: every `run()` is `async` and driven by
 * `void run()` from a click handler, so a rejection inside one is unhandled and
 * would otherwise be invisible to the test. Attach before `boot`, assert after
 * the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * The lab's own `<header class="cl-hero">` is a direct child of `<div id="app">`
 * — a plain div, NOT sectioning content — so nothing scopes it out of the banner
 * role on its own. What demotes it is the `dedupeBanner()` script in
 * `index.html`, which stamps `role="group"` on every stray `<header>`. This
 * asserts the OUTCOME rather than the mechanism, so a change to either the
 * markup or the script is caught. (It also matters for the axe rules below: the
 * hero aside is `role="complementary"`, and `landmark-complementary-is-top-level`
 * passes only because the hero around it is a `group` and not a landmark.)
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. An emulation that silently did nothing would
 * leave the gate certifying a different rendering than the one it claims to —
 * and here specifically it would drive `playFlight()`'s ANIMATED path, whose two
 * `await wait(...)`s mean the results region renders ~1s after the click, so
 * every "scan straight after the click" would race the render.
 *
 * The theme is seeded through `localStorage` rather than by clicking the toggle,
 * which also pins down a real failure mode: `index.html`'s anti-flash script
 * reads `localStorage.getItem('theme')` and the toggle writes
 * `localStorage.setItem('theme', ...)`. If those two keys ever drift apart the
 * theme silently stops persisting, and this boot would fail on the `data-theme`
 * assertion rather than quietly scanning dark twice.
 *
 * The defaults are asserted because WHICH HALF of this lab gets measured depends
 * on them, and they are not the obvious half:
 *
 *  - The strip panel ships BOUND (`#binding-bound`, "the real default") and
 *    UNSTRIPPED. So the reader's first run is the one where the defense holds,
 *    not the downgrade — and the old gate's very first action was `#strip-play`,
 *    which strips, unbinds, and runs, so it never once saw the shipped
 *    configuration.
 *  - The sentinel panel ships with BOTH boxes checked and renders itself on
 *    mount, so a green `.chip-ok` "Rollback DETECTED" is already on screen at
 *    first paint. The old gate immediately unchecked one and scanned only the
 *    red `.chip-alarm`.
 *  - The fail-open panel ships on `fail-open` with its output EMPTY.
 *  - The server lane, the results region, the compare region and the policy grid
 *    are all empty until something is run; an empty region is its own layout.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);

  // All seven panels are mounted by `src/main.ts` into a <main> it creates, so a
  // navigation that resolves proves nothing.
  for (const id of ['intro', 'strip', 'policy', 'sentinel', 'failopen', 'history', 'scope']) {
    await expect(page.locator(`#${id}`)).toBeVisible();
  }

  // ── The strip panel's shipped defaults: BOUND and UNSTRIPPED ──────────────
  await expect(page.locator('#binding-bound')).toBeChecked();
  await expect(page.locator('#binding-unbound')).not.toBeChecked();
  await expect(page.locator('#policy-preferred')).toBeChecked();
  await expect(page.locator('#policy-required')).not.toBeChecked();
  // Both groups still offered, neither struck, attacker idle.
  await expect(page.locator('#strip .lane-client .pkt-entry')).toHaveCount(2);
  await expect(page.locator('#strip .pkt-struck')).toHaveCount(0);
  await expect(page.locator('#strip .lane-attacker .lane-idle')).toHaveText(
    'passing bytes through untouched'
  );
  await expect(page.locator('#strip .scissors')).toHaveCount(0);
  // Nothing has run: the server lane, the results and the compare rail are all
  // empty, and the MAC-diff disclosure does not exist yet.
  await expect(page.locator('#strip .lane-server .lane-title')).toHaveCount(0);
  await expect(page.locator('#strip .strip-results .chip')).toHaveCount(0);
  await expect(page.locator('#strip .compare-card')).toHaveCount(0);

  // ── The sentinel panel ships CHECKED/CHECKED and has already rendered ─────
  await expect(page.getByLabel('Server writes the sentinel')).toBeChecked();
  await expect(page.getByLabel('Client checks the sentinel')).toBeChecked();
  await expect(page.locator('#sentinel .chip-ok')).toContainText('Rollback DETECTED');
  await expect(page.locator('#sentinel .chip-alarm')).toHaveCount(0);

  // ── Fail-open ships on `fail-open`, with nothing run ──────────────────────
  await expect(page.locator('#retry-fail-open')).toBeChecked();
  await expect(page.locator('#retry-fail-closed')).not.toBeChecked();
  await expect(page.locator('#failopen .attempt')).toHaveCount(0);
  await expect(page.locator('#policy .policy-card')).toHaveCount(0);

  // Exactly one disclosure ships on the page, and it ships shut. The MAC-diff
  // `.expert` panel is created per run and so cannot exist yet.
  await expect(page.locator('details')).toHaveCount(1);
  await expect(page.locator('details[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all. It matters on this
 * page because almost everything it renders is monospace hex: a 32-byte
 * transcript hash is 96 characters of `white-space: nowrap`, and there are eight
 * such rows inside the MAC diff alone. Each is meant to scroll inside its own
 * `.byteblock`; the assertion here is that none of them scrolls the DOCUMENT.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That
    // cost a run elsewhere in this fleet, and this lab is full of such decoys:
    // every `.byteblock` is `overflow-x: auto` around nowrap hex far wider than
    // the box, and `.flight-track` is `overflow: hidden` around a packet that
    // deliberately travels outside it.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This lab already handles its known case — `render.ts`'s `byteRegion()` builds
 * every `.byteblock` with `tabindex="0"`, `role="group"` and an `aria-label`, and
 * that is the only scroller it ships. The assertion stays because the helper is
 * a convention, not an enforcement: the next `overflow-x: auto` someone adds by
 * hand is the one that breaks it, and the failure is silent until a keyboard
 * user meets it. It is worth more here than in most labs, because the content
 * inside those scrollers is the evidence the whole demo turns on.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the
 * committed workflow, and a run with it set prints every finding as it happens
 * and then fails at the end, so a green collection run cannot be mistaken for a
 * green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything.
 *
 * Without this a collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function expectScrollersReachableSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectScrollersReachable(page, label);
  try {
    await expectScrollersReachable(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

async function expectNoHorizontalOverflowSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoHorizontalOverflow(page, label);
  try {
    await expectNoHorizontalOverflow(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * Scan the page as it currently stands.
 *
 * Six assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters more here than in most labs, since
 *    every surface this demo uses to state an outcome is a `color-mix()` axe
 *    declines to resolve: all three verdict chips, both MAC-diff badges, both
 *    "aha" boxes and every highlighted byte.
 *    Everything else in that bucket is a real result axe simply could not
 *    finish — including `aria-prohibited-attr`, which is where an `aria-label`
 *    on a role-less element hides, a defect that never reaches the violations
 *    array at all. This page puts `aria-label` on six things, one of which is a
 *    `<code>` element that carries `role="group"` precisely so the label is
 *    legal; that role is easy to drop by accident and this is what would notice.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *    Note the one thing it cannot reach, `::before`/`::after` generated
 *    content; see the header of `contrast.ts` for why that blind spot is empty
 *    on this page.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write `runOnly`,
  // so the second call SILENTLY REPLACES the first — the axe-core/playwright
  // source says so in as many words ("Cannot be used with AxeBuilder#withTags").
  // Chained as `.withTags(TAGS).withRules([...4 landmark rules])`, which is the
  // form this gate shipped with, axe therefore ran those four best-practice
  // rules and NOT ONE WCAG RULE: measured on this page, the chained form
  // executes 4 rules where `withTags` alone executes 63. A green result meant
  // "no duplicate landmarks", and nothing whatsoever about WCAG A/AA — while
  // reading exactly like a full pass. Running the two sets separately and
  // merging is the only way to have both; the landmark four are wanted because
  // they are best-practice rather than WCAG-tagged, so `withTags` alone does not
  // reach them, and this page has the shape they catch: a shared sticky
  // <header role="banner"> above a lab hero that is itself a <header>, with an
  // <aside role="complementary"> inside that hero.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await expectScrollersReachableSoft(page, label);
  await expectNoHorizontalOverflowSoft(page, label);
  await expectNoNewNonTextFailures(page, label);
}

// ── Locators and small helpers the drive uses ────────────────────────────────

/** The strip panel's two `role="status"` chips: the neutral fact, then the verdict. */
const stripResult = (page: Page) => page.locator('#strip .strip-results .chip-neutral');
const stripVerdict = (page: Page) => page.locator('#strip .strip-results .indicator-pair .chip').nth(1);

/** Open one `<details>` the way a reader does, and assert it opened. */
async function openDisclosure(page: Page, summaryText: RegExp): Promise<void> {
  const summary = page.locator('details > summary').filter({ hasText: summaryText });
  await summary.click();
  await expect(summary.locator('..')).toHaveAttribute('open', '');
}

/**
 * Strip one group from the ClientHello by clicking its ✕, the way a reader does.
 *
 * `renderPacket()` rebuilds the whole list on every removal, so the button that
 * was clicked is detached mid-handler. Waiting on the resulting struck entry in
 * the attacker's lane — rather than on the button — is what makes this stable.
 */
async function stripGroup(page: Page, label: string): Promise<void> {
  const before = await page.locator('#strip .pkt-struck').count();
  await page.getByRole('button', { name: `Strip ${label} from the ClientHello` }).click();
  await expect(page.locator('#strip .pkt-struck')).toHaveCount(before + 1);
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Six things shape this drive:
 *
 *  - THE SHIPPED CONFIGURATION IS RUN FIRST. The lab arrives BOUND and
 *    UNSTRIPPED, so the reader's first run is a clean TLS 1.3 handshake that
 *    ends SECURE — and that run is also the ONLY route on the whole page to
 *    `.vb-ok`, the "identical" badge the MAC diff shows when the two transcripts
 *    agree. The gate this replaces opened with `#strip-play`, which strips and
 *    unbinds before doing anything, so it never rendered a `.vb-ok` at all.
 *
 *  - ALL FIVE VERDICTS, EACH WITH ITS OWN TONE. `SECURE` and `DEFENSE_HELD` are
 *    `.chip-ok` green, `DOWNGRADE_ALARM` is `.chip-alarm` red, `POLICY_DENIED`
 *    and `NO_CONNECTION` are `.chip-warn` amber. Two of those five (the warn
 *    pair) were unreachable in the old drive, which means `--warn-text` and
 *    `--warn-strong` had never been measured against the surface they land on in
 *    either theme. Reaching them takes specific configurations, noted inline.
 *
 *  - THE MAC DIFF IS OPENED IN BOTH OUTCOMES. It is built only when transcript
 *    binding is on, and it renders differently depending on whether the two
 *    transcripts agree: `.vb-ok` twice and no diff marks when they do,
 *    `.vb-fail` twice and a `<mark class="byte-changed">` on every differing
 *    byte when they do not. Both are opened by clicking the summary.
 *
 *  - EVERY BRANCH OF EVERY FORK, INCLUDING THE EMPTY AND ERROR SHAPES: the
 *    packet with one entry struck and with both struck (`.pkt-empty`), the
 *    compare rail, the policy panel's two cards, all FOUR sentinel checkbox
 *    combinations — the shipped DETECTED state plus the two distinct MISSED
 *    messages — and both fail-open retry policies.
 *
 *  - EVERY RESET. `Reset offer` returns a completed run to the empty state,
 *    clearing the server lane, the results and the compare rail at once. An
 *    empty region is its own layout and its own copy.
 *
 *  - NO FIXED TIMEOUTS. Every panel computes on the click — genuinely, including
 *    a real ML-KEM-768 encapsulation, which is why the waits are on rendered
 *    output rather than on a duration. Under the reduced motion this gate
 *    asserts, `playFlight()` returns synchronously, so results land as soon as
 *    the handshake resolves.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);
  const strip = page.locator('#strip');
  const runBtn = page.locator('#strip-run');

  await scanAt('first paint, everything idle and nothing run');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('skip link focused');

  await openDisclosure(page, /Or drive it step by step/);
  await scanAt('step-by-step guide disclosure open');

  // ── The shipped configuration: bound, unstripped, preferred → SECURE ──────
  await runBtn.click();
  await expect(stripResult(page)).toContainText('Handshake COMPLETED on X25519MLKEM768');
  await expect(stripVerdict(page)).toContainText('SECURE — post-quantum key agreed');
  await expect(strip.locator('.aha')).toHaveCount(0);
  await scanAt('shipped config runs clean, post-quantum key agreed');

  // The only route on the page to the "identical" badge.
  await openDisclosure(page, /Show the Finished MAC/);
  await expect(strip.locator('.vb-ok')).toHaveCount(2);
  await expect(strip.locator('.vb-fail')).toHaveCount(0);
  // The clean-run wording. This used to read "deleted 0 bytes … plus its
  // -6-byte X25519MLKEM768 key_share" — a negative length, for a deletion that
  // did not happen, naming a group that was still in the offer — because the
  // sentence was unconditional and the old gate never ran a clean bound
  // handshake to see it.
  await expect(strip.locator('.diff-delete')).toHaveText(
    'The attacker deleted nothing: the server received the ClientHello byte for byte, so both sides hash the same transcript.'
  );
  await scanAt('MAC diff open on a clean run, both views identical');

  // ── Strip the hybrid group, still bound → DEFENSE HELD ────────────────────
  await stripGroup(page, 'X25519MLKEM768');
  await expect(strip.locator('.lane-attacker .scissors')).toBeVisible();
  await expect(strip.locator('.lane-client .pkt-entry')).toHaveCount(1);
  await scanAt('hybrid group struck from the offer, not yet run');

  await runBtn.click();
  await expect(stripResult(page)).toContainText('Handshake ABORTED — Finished MAC mismatch');
  await expect(stripVerdict(page)).toContainText('DEFENSE HELD');
  await expect(strip.locator('.aha-ok')).toBeVisible();
  await scanAt('bound strip aborts, defense held');

  await openDisclosure(page, /Show the Finished MAC/);
  await expect(strip.locator('.vb-fail')).toHaveCount(2);
  await expect(strip.locator('mark.byte-changed').first()).toBeVisible();
  // Names the group that was actually removed, and every byte count is positive.
  await expect(strip.locator('.diff-delete')).toHaveText(
    /^The attacker deleted \d+ bytes from the ClientHello: the 2-byte codepoint for X25519MLKEM768 in supported_groups, plus the \d+ bytes of matching key_share\.$/
  );
  await scanAt('MAC diff open on a caught strip, differing bytes marked');

  // ── Same strip, unbound → the canonical downgrade ─────────────────────────
  await page.locator('#binding-unbound').check();
  await runBtn.click();
  await expect(stripResult(page)).toContainText('Handshake COMPLETED on x25519');
  await expect(stripVerdict(page)).toContainText('DOWNGRADE — ALARM');
  await expect(strip.locator('.aha')).toContainText('neither side ever learns');
  // Unbound means no Finished record at all, so the MAC diff cannot exist.
  await expect(strip.locator('.strip-results details')).toHaveCount(0);
  await scanAt('unbound strip completes on x25519, downgrade alarm');

  // ── The amber half of the palette, which nothing else reaches ─────────────
  // POLICY_DENIED needs unbound + a stripped hybrid + "PQC required": with
  // binding on, the Finished check fires first and the verdict is DEFENSE_HELD
  // before policy is ever consulted.
  await page.locator('#policy-required').check();
  await runBtn.click();
  await expect(stripResult(page)).toContainText(
    'Handshake ABORTED — policy refused a classical-only suite'
  );
  await expect(stripVerdict(page)).toContainText('CONNECTION DENIED');
  await expect(strip.locator('.chip-warn')).toHaveCount(1);
  await scanAt('required-PQ refuses the downgraded suite (amber verdict)');

  // NO_CONNECTION needs BOTH groups struck — which is also the only route to
  // the `.pkt-empty` "nothing left to offer" row.
  await stripGroup(page, 'x25519');
  await expect(strip.locator('.pkt-empty')).toBeVisible();
  await expect(strip.locator('.lane-client .pkt-entry')).toHaveCount(0);
  await scanAt('every group struck, nothing left to offer');

  await runBtn.click();
  await expect(stripResult(page)).toContainText('Handshake FAILED — no mutually supported group');
  await expect(stripVerdict(page)).toContainText('NO SHARED GROUP');
  await expect(strip.locator('.lane-pick')).toContainText('aborts — no mutually supported group');
  await scanAt('no shared group, handshake cannot proceed (amber verdict)');

  // ── Reset returns all three output regions to empty at once ───────────────
  await page.locator('#strip-reset').click();
  await expect(strip.locator('.lane-client .pkt-entry')).toHaveCount(2);
  await expect(strip.locator('.strip-results .chip')).toHaveCount(0);
  await expect(strip.locator('.lane-attacker .lane-idle')).toBeVisible();
  await scanAt('offer reset, every output region empty again');

  // ── One action, both worlds side by side ──────────────────────────────────
  // Note this leaves `policy` on "required", so the rail is the required-policy
  // pair — a different pair of verdicts from the preferred one below.
  await page.locator('#strip-compare').click();
  await expect(strip.locator('.compare-card')).toHaveCount(2);
  await expect(strip.locator('.compare-title')).toContainText('PQC required');
  await scanAt('compare rail under required policy');

  await page.locator('#policy-preferred').check();
  await page.locator('#strip-compare').click();
  await expect(strip.locator('.compare-title')).toContainText('PQC preferred');
  await expect(strip.locator('.compare-card').nth(0)).toContainText('DOWNGRADE — ALARM');
  await expect(strip.locator('.compare-card').nth(1)).toContainText('DEFENSE HELD');
  await scanAt('compare rail under preferred policy, both verdicts at once');

  // ── The one-click preset, and the transient label the Copy button flashes ──
  await page.locator('#strip-play').click();
  await expect(stripVerdict(page)).toContainText('DOWNGRADE — ALARM');
  await expect(page.locator('#binding-unbound')).toBeChecked();
  await scanAt('Play-the-downgrade preset');

  // `copyLink()` swaps the label for 1600ms, so this is measured with the
  // narrowed walk and then the label is re-asserted — proving the measurement
  // was taken while the flashed state was still on screen. Which of the two
  // labels appears depends on whether the clipboard is permitted, so accept
  // either; both are real renderings of the same state.
  const copyBtn = page.locator('#strip-copylink');
  await copyBtn.click();
  await expect(copyBtn).toHaveText(/Link copied|Link in address bar/);
  const flashed = Array.from(
    new Set(formatContrastFailures(await auditContrast(page, '.preset-row *')))
  );
  await expect(copyBtn).toHaveText(/Link copied|Link in address bar/);
  softExpect(flashed, `measured contrast failures in state: ${theme} / copy-link flashed`, []);
  await expect(copyBtn).toHaveText('Copy link', { timeout: 5_000 });

  // ── Panel 3: the same strip under both server policies at once ────────────
  await page.locator('#policy-run').click();
  await expect(page.locator('#policy .policy-card')).toHaveCount(2);
  await expect(page.locator('#policy .policy-card').nth(0)).toContainText('DOWNGRADE — ALARM');
  await expect(page.locator('#policy .policy-card').nth(1)).toContainText('CONNECTION DENIED');
  await scanAt('policy panel, preferred vs required side by side');

  // ── Panel 4: all four sentinel combinations ───────────────────────────────
  const writes = page.getByLabel('Server writes the sentinel');
  const checks = page.getByLabel('Client checks the sentinel');
  const sentinelChip = page.locator('#sentinel .chip');

  await checks.uncheck();
  await expect(sentinelChip).toContainText('the sentinel is present but the client never checks it');
  await scanAt('sentinel written but never checked, rollback missed');

  await writes.uncheck();
  await expect(sentinelChip).toContainText('this server did not write the sentinel');
  await scanAt('sentinel neither written nor checked, rollback missed');

  await checks.check();
  await expect(sentinelChip).toContainText('this server did not write the sentinel');
  await scanAt('client checks, but this server wrote no sentinel');

  await writes.check();
  await expect(sentinelChip).toContainText('Rollback DETECTED');
  await scanAt('sentinel written and checked, rollback detected');

  // ── Panel 5: both retry policies ──────────────────────────────────────────
  await page.locator('#failopen-run').click();
  await expect(page.locator('#failopen .attempt')).toHaveCount(2);
  await expect(page.locator('#failopen .chip-alarm')).toContainText(
    'the attacker won by breaking the connection twice'
  );
  await scanAt('fail-open retry walks the connection back to x25519');

  await page.locator('#retry-fail-closed').check();
  await page.locator('#failopen-run').click();
  await expect(page.locator('#failopen .attempt')).toHaveCount(1);
  await expect(page.locator('#failopen .chip-ok')).toContainText('the client refused to weaken');
  await scanAt('fail-closed gives up, one attempt and no downgrade');
}
