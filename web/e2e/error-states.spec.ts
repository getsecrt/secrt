import { test, expect } from '@playwright/test';

test.describe('Error states', () => {
  test('claim URL with no fragment shows incomplete link error', async ({
    page,
  }) => {
    // Navigate to a claim path without a hash fragment
    await page.goto('/s/nonexistent-id');
    await expect(page.getByText('Secret Unavailable')).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.getByText(/incomplete|missing/i)).toBeVisible();
  });

  test('claim URL with invalid fragment shows malformed error', async ({
    page,
  }) => {
    await page.goto('/s/nonexistent-id#not-valid-base64url!!!');
    await expect(page.getByText('Secret Unavailable')).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.getByText(/malformed|invalid/i)).toBeVisible();
  });

  test('nonexistent secret ID shows unavailable', async ({ page }) => {
    // Valid-format base64url key (32 bytes = 43 chars base64url)
    const fakeKey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    await page.goto(`/s/does-not-exist-000#${fakeKey}`);
    await expect(page.getByText('Secret Unavailable')).toBeVisible({
      timeout: 10_000,
    });
  });

  test('unknown route shows not found', async ({ page }) => {
    await page.goto('/this-route-does-not-exist');
    await expect(page.getByText('Not found')).toBeVisible();
  });
});
