import { test, expect } from '@playwright/test';
import { sendSecret, claimSecret } from './helpers';

test.describe('Send and claim flow', () => {
  test('plaintext secret round-trip', async ({ page, context }) => {
    const secret = `e2e test secret ${Date.now()}`;
    const shareUrl = await sendSecret(page, secret);

    expect(shareUrl).toContain('/s/');
    expect(shareUrl).toContain('#');

    // Claim on a fresh page (same page reuse can cause SPA state issues)
    const claimPage = await context.newPage();
    const claimed = await claimSecret(claimPage, shareUrl);
    expect(claimed).toBe(secret);
    await claimPage.close();
  });

  test('passphrase-protected secret: wrong then correct', async ({
    page,
    context,
  }) => {
    const secret = `passphrase protected ${Date.now()}`;
    const passphrase = 'hunter2';
    const shareUrl = await sendSecret(page, secret, { passphrase });

    // Parse URL for claiming
    const parsed = new URL(shareUrl);
    const pathWithHash = parsed.pathname + parsed.hash;

    // Claim on a fresh page — click through the confirm screen first
    const claimPage = await context.newPage();
    await claimPage.goto(pathWithHash);

    await expect(
      claimPage.getByRole('button', { name: 'View Secret' }),
    ).toBeVisible({ timeout: 15_000 });
    await claimPage.getByRole('button', { name: 'View Secret' }).click();

    await expect(claimPage.getByText('Passphrase Required')).toBeVisible({
      timeout: 15_000,
    });

    // Wrong passphrase
    await claimPage.locator('#claim-passphrase').fill('wrong-password');
    await claimPage.getByRole('button', { name: 'Decrypt' }).click();
    await expect(claimPage.getByText('Wrong passphrase')).toBeVisible({
      timeout: 10_000,
    });

    // Correct passphrase
    await claimPage.locator('#claim-passphrase').fill(passphrase);
    await claimPage.getByRole('button', { name: 'Decrypt' }).click();
    await expect(claimPage.getByText('Secret Decrypted')).toBeVisible({
      timeout: 15_000,
    });

    const content = await claimPage.locator('textarea').inputValue();
    expect(content?.trim()).toBe(secret);

    await claimPage.close();
  });

  test('double-claim returns unavailable', async ({ page, context }) => {
    const secret = `one-time ${Date.now()}`;
    const shareUrl = await sendSecret(page, secret);

    // First claim succeeds
    await claimSecret(page, shareUrl);

    // Second claim on a new page should fail after clicking "View Secret"
    const parsed = new URL(shareUrl);
    const pathWithHash = parsed.pathname + parsed.hash;
    const page2 = await context.newPage();
    await page2.goto(pathWithHash);

    await expect(
      page2.getByRole('button', { name: 'View Secret' }),
    ).toBeVisible({ timeout: 15_000 });
    await page2.getByRole('button', { name: 'View Secret' }).click();

    await expect(page2.getByText('Secret Unavailable')).toBeVisible({
      timeout: 15_000,
    });

    await page2.close();
  });
});
