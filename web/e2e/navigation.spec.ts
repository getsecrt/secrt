import { test, expect } from '@playwright/test';

test.describe('Navigation', () => {
  test('home page loads and shows send form', async ({ page }) => {
    await page.goto('/');
    await expect(
      page.getByPlaceholder('Enter your secret...'),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Create secret' }),
    ).toBeVisible();
  });

  test('home nav control navigates home', async ({ page }) => {
    await page.goto('/how-it-works');
    await expect(page.getByText('How secrt Works')).toBeVisible();

    const createLink = page.getByRole('link', { name: /^Create$/ }).first();
    if (await createLink.isVisible()) {
      await createLink.click();
    } else {
      await page.getByRole('button', { name: 'Open menu' }).click();
      await page.getByRole('link', { name: /^Create$/ }).first().click();
    }

    await expect(
      page.getByPlaceholder('Enter your secret...'),
    ).toBeVisible();
  });

  test('how-it-works page loads', async ({ page }) => {
    await page.goto('/how-it-works');
    await expect(page.getByText('How secrt Works')).toBeVisible();
    await expect(
      page.getByRole('heading', { name: 'Overview', exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole('heading', { name: 'Encryption' }),
    ).toBeVisible();
    await expect(
      page.getByRole('heading', { name: 'Open Source' }),
    ).toBeVisible();
  });

  test('how-it-works home link navigates home', async ({ page }) => {
    await page.goto('/how-it-works');
    await page.getByRole('link', { name: 'Home' }).click();
    await expect(
      page.getByPlaceholder('Enter your secret...'),
    ).toBeVisible();
  });

  test('how-it-works link on send page navigates to details', async ({
    page,
  }) => {
    await page.goto('/');
    await page.getByRole('link', { name: 'How secrt Works →' }).click();
    await expect(page.getByText('How secrt Works')).toBeVisible();
  });
});
