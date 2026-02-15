import { test, expect } from '@playwright/test';
import {
  installFakePasskey,
  registerPasskeyAccount,
} from './helpers';

function uniqueId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
}

test.describe('Settings: API keys and account deletion', () => {
  test('creates and revokes an API key', async ({ page, browserName }) => {
    test.skip(
      browserName !== 'chromium' || test.info().project.name !== 'chromium',
      'Settings auth E2E currently runs on desktop Chromium only',
    );

    const credentialId = uniqueId('cred-key');
    await installFakePasskey(page, { createId: credentialId, getId: credentialId });
    await registerPasskeyAccount(page, { displayName: `Key User ${Date.now()}` });

    await page.goto('/settings');
    await expect(
      page.getByRole('heading', { name: 'API Keys', exact: true }),
    ).toBeVisible();

    await page.getByRole('button', { name: 'Create Key' }).click();
    await expect(page.getByText('API Key Created')).toBeVisible({
      timeout: 15_000,
    });

    const newKey = (await page.locator('code').first().textContent())?.trim() ?? '';
    expect(newKey.startsWith('ak2_')).toBeTruthy();

    await expect(page.getByText('Active')).toBeVisible();
    await page.getByRole('button', { name: 'Revoke' }).first().click();
    await expect(page.getByText('Revoked')).toBeVisible({
      timeout: 15_000,
    });
  });

  test('deletes account and blocks future login for deleted passkey', async ({
    page,
    browserName,
  }) => {
    test.skip(
      browserName !== 'chromium' || test.info().project.name !== 'chromium',
      'Settings auth E2E currently runs on desktop Chromium only',
    );

    const credentialId = uniqueId('cred-delete');
    await installFakePasskey(page, { createId: credentialId, getId: credentialId });
    await registerPasskeyAccount(page, {
      displayName: `Delete User ${Date.now()}`,
    });

    await page.goto('/settings');
    await page.getByRole('button', { name: 'Delete Account' }).click();

    const confirmDelete = page.getByRole('button', { name: 'Delete', exact: true });
    await expect(confirmDelete).toBeDisabled();
    await page.getByPlaceholder('Type DELETE').fill('DELETE');
    await expect(confirmDelete).toBeEnabled();

    await confirmDelete.click();
    await expect(page.getByPlaceholder('Enter your secret...')).toBeVisible({
      timeout: 15_000,
    });

    await page.goto('/settings');
    await expect(page.getByRole('heading', { name: 'Log In' })).toBeVisible({
      timeout: 15_000,
    });

    await page.goto('/login');
    await page.getByRole('button', { name: 'Log in with Passkey' }).click();
    await expect(page.getByRole('alert')).toContainText('not recognized');
  });
});
