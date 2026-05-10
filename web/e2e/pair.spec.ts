import { test, expect } from '@playwright/test';

/**
 * /pair is session-gated, like /device and /app-login. The redirect must
 * preserve the original query string so a QR-scanned deep link survives
 * the round-trip through /login.
 */
test.describe('/pair routing', () => {
  test('unauthenticated visit redirects to /login with the original URL preserved', async ({
    page,
  }) => {
    await page.goto('/pair?mode=join&code=K7MQ-3F2A');
    await expect(page).toHaveURL(/\/login\?redirect=/, { timeout: 15_000 });
    const url = new URL(page.url());
    const redirect = url.searchParams.get('redirect');
    expect(redirect).toBe('/pair?mode=join&code=K7MQ-3F2A');
  });

  test('bare /pair without auth redirects to /login preserving the path', async ({
    page,
  }) => {
    await page.goto('/pair');
    await expect(page).toHaveURL(/\/login\?redirect=/, { timeout: 15_000 });
    const url = new URL(page.url());
    expect(url.searchParams.get('redirect')).toBe('/pair');
  });
});

/**
 * Full happy-path requires two browser contexts that can both authenticate
 * as the same user. The shared passkey fixture in `helpers.ts` does not
 * round-trip signatures through real WebAuthn, so the second context can't
 * currently log in with the first context's registered credential. Marking
 * skipped with a pointer to the plan rather than letting bitrot accumulate.
 *
 * See `~/.claude/plans/let-s-review-taskmaster-plans-task-68-am-jazzy-cloud.md`
 * §"Tests" — PR 2 row — for the intended assertions.
 */
test.skip('two-context AMK roundtrip', async () => {
  // 1. Context A registers a passkey account, generates an AMK locally.
  // 2. Context B (same browser, separate context) logs in with the same
  //    credential — no AMK in this context's IndexedDB.
  // 3. Context B navigates to /pair?mode=display&role=receive, captures
  //    the displayed code.
  // 4. Context A navigates to /pair?mode=join&code=<code> and approves.
  // 5. Assert Context B's IndexedDB now has an AMK and shows success.
});

test.skip('cross-account commit mismatch refuses to store', async () => {
  // 1. Register Account A in context A.
  // 2. Register Account B in context B (different credential, server returns
  //    a different commit on /amk/commit).
  // 3. Drive the pair flow as if A were sending to B; B's /amk/commit returns
  //    409 and B's IndexedDB stays empty.
});
