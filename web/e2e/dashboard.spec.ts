import { test, expect } from '@playwright/test';
import {
  installFakePasskey,
  registerPasskeyAccount,
  sendSecret,
} from './helpers';

function uniqueId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
}

test.describe('Dashboard management', () => {
  test('redirects unauthenticated users to login', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page.getByRole('heading', { name: 'Log In' })).toBeVisible({
      timeout: 15_000,
    });
  });

  test('burns a secret from dashboard and claim becomes unavailable', async ({
    page,
    context,
    browserName,
  }) => {
    test.skip(
      browserName !== 'chromium' || test.info().project.name !== 'chromium',
      'Dashboard auth E2E currently runs on desktop Chromium only',
    );

    const credentialId = uniqueId('cred-dashboard');
    await installFakePasskey(page, {
      createId: credentialId,
      getId: credentialId,
    });
    await registerPasskeyAccount(page, {
      displayName: `Dash User ${Date.now()}`,
    });

    const secretText = `dashboard-burn ${Date.now()}`;
    const shareUrl = await sendSecret(page, secretText);
    const parsedShare = new URL(shareUrl);
    const secretId = parsedShare.pathname.split('/').at(-1) ?? '';
    const sharePathWithHash = parsedShare.pathname + parsedShare.hash;

    await page.goto('/dashboard');
    await expect(page.getByText('Your Secrets')).toBeVisible();
    await expect(page.getByText(secretId)).toBeVisible({
      timeout: 15_000,
    });

    await page.locator('button.btn-destructive-subtle').first().click();
    await page.getByRole('button', { name: 'Burn it' }).click();

    await expect(page.getByText(secretId)).toHaveCount(0);
    await expect(page.getByText('You have no active secrets.')).toBeVisible();

    const claimPage = await context.newPage();
    await claimPage.goto(sharePathWithHash);
    // Claim page now shows a confirmation step before attempting to claim
    await claimPage.getByRole('button', { name: 'View Secret' }).click();
    await expect(claimPage.getByText('Secret Unavailable')).toBeVisible({
      timeout: 15_000,
    });
    await claimPage.close();
  });
});
