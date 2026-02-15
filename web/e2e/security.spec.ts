import { test, expect } from '@playwright/test';
import { sendSecret } from './helpers';

test.describe('Security', () => {
  test('URL fragment is not sent to server in network requests', async ({
    page,
  }) => {
    const secret = `security test ${Date.now()}`;
    const shareUrl = await sendSecret(page, secret);

    // Extract the fragment (key) from the share URL
    const parsed = new URL(shareUrl);
    const fragment = parsed.hash.slice(1);
    const pathWithHash = parsed.pathname + parsed.hash;
    expect(fragment.length).toBeGreaterThan(0);

    // Navigate to claim page and monitor network
    const requests: string[] = [];
    page.on('request', (req) => {
      requests.push(req.url());
    });

    await page.goto(pathWithHash);
    await page.getByRole('button', { name: 'View Secret' }).click();
    await expect(page.getByText('Secret Decrypted')).toBeVisible({
      timeout: 15_000,
    });

    // Verify that no request URL contains the fragment/key
    for (const url of requests) {
      expect(url).not.toContain(fragment);
    }
  });

  test('fragment is not visible in page text content', async ({
    page,
    context,
  }) => {
    const secret = `fragment hidden ${Date.now()}`;
    const shareUrl = await sendSecret(page, secret);

    const parsed = new URL(shareUrl);
    const fragment = parsed.hash.slice(1);
    const pathWithHash = parsed.pathname + parsed.hash;

    const claimPage = await context.newPage();
    await claimPage.goto(pathWithHash);
    await claimPage.getByRole('button', { name: 'View Secret' }).click();
    // Wait for the claim flow — might need longer due to crypto operations
    await expect(claimPage.getByText('Secret Decrypted')).toBeVisible({
      timeout: 15_000,
    });

    // The raw URL key should not appear in any visible text
    const bodyText = await claimPage.locator('body').textContent();
    expect(bodyText).not.toContain(fragment);

    await claimPage.close();
  });
});
