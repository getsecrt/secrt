import { test, expect } from '@playwright/test';
import {
  installFakePasskey,
  setFakePasskeyIds,
  registerPasskeyAccount,
  loginWithPasskey,
} from './helpers';

function uniqueId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
}

test.describe('Passkey auth flow', () => {
  test('registers and logs in again with the same passkey', async ({
    page,
    browserName,
  }) => {
    test.skip(
      browserName !== 'chromium' || test.info().project.name !== 'chromium',
      'Auth passkey E2E currently runs on desktop Chromium only',
    );

    const credentialId = uniqueId('cred-auth');
    await installFakePasskey(page, { createId: credentialId, getId: credentialId });

    const displayName = `Auth User ${Date.now()}`;
    await registerPasskeyAccount(page, { displayName });

    await page.goto('/settings');
    await expect(page.getByText('Your Account')).toBeVisible();
    await expect(page.getByRole('main').getByText(displayName)).toBeVisible();

    // Reset persisted session and verify login flow from a fresh app instance.
    await page.evaluate(() => localStorage.removeItem('session_token'));
    const loginPage = await page.context().newPage();

    await loginPage.goto('/dashboard');
    await expect(loginPage.getByRole('heading', { name: 'Log In' })).toBeVisible({
      timeout: 15_000,
    });

    await loginWithPasskey(loginPage);
    await loginPage.goto('/settings');
    await expect(loginPage.getByRole('main').getByText(displayName)).toBeVisible();
    await loginPage.close();
  });

  test('shows friendly unknown-credential error', async ({
    page,
    browserName,
  }) => {
    test.skip(
      browserName !== 'chromium' || test.info().project.name !== 'chromium',
      'Auth passkey E2E currently runs on desktop Chromium only',
    );

    const knownCredentialId = uniqueId('cred-known');
    await installFakePasskey(page, {
      createId: knownCredentialId,
      getId: knownCredentialId,
    });
    await registerPasskeyAccount(page, { displayName: `Known ${Date.now()}` });

    await page.evaluate(() => localStorage.removeItem('session_token'));

    const loginPage = await page.context().newPage();
    await loginPage.goto('/login');
    await setFakePasskeyIds(loginPage, { getId: uniqueId('cred-unknown') });
    await loginPage.getByRole('button', { name: 'Log in with Passkey' }).click();

    await expect(loginPage.getByRole('alert')).toContainText('not recognized');
    await loginPage.close();
  });
});
