import { test, expect } from '@playwright/test';
import { sendSecret } from './helpers';

test.describe('Clipboard', () => {
  test('copy share URL button works', async ({ page, context, browserName }) => {
    // Skip on WebKit — clipboard API is restricted and permission not supported
    test.skip(browserName === 'webkit', 'WebKit clipboard requires HTTPS');

    // Grant clipboard permissions for Chromium
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);

    const secret = `clipboard test ${Date.now()}`;
    const shareUrl = await sendSecret(page, secret);

    // Click copy button
    await page.getByRole('button', { name: /^Copy/ }).click();
    await expect(page.getByText('Copied!')).toBeVisible();

    // Verify clipboard content
    const clipboardText = await page.evaluate(() =>
      navigator.clipboard.readText(),
    );
    expect(clipboardText).toBe(shareUrl);
  });
});
