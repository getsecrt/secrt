import { type Page, expect } from '@playwright/test';

/**
 * Send a text secret via the UI and return the share URL.
 */
export async function sendSecret(
  page: Page,
  text: string,
  opts?: { passphrase?: string },
): Promise<string> {
  await page.goto('/');
  await page.getByPlaceholder('Enter your secret...').fill(text);

  if (opts?.passphrase) {
    await page.locator('#passphrase').fill(opts.passphrase);
  }

  await page.getByRole('button', { name: 'Create secret' }).click();
  await expect(page.getByText('Secret created')).toBeVisible({
    timeout: 15_000,
  });

  const urlBox = page.getByRole('textbox', { name: 'Share URL' });
  const shareUrl = await urlBox.textContent();
  if (!shareUrl) throw new Error('Share URL not found');
  return shareUrl;
}

/**
 * Navigate to a share URL and claim the secret.
 * Returns the decrypted text content.
 */
export async function claimSecret(
  page: Page,
  shareUrl: string,
  opts?: { passphrase?: string },
): Promise<string> {
  // Parse the share URL to get path + fragment, navigate relative to baseURL
  // Use waitUntil: 'load' to ensure a full page load (not just SPA navigation)
  const url = new URL(shareUrl);
  const pathWithHash = url.pathname + url.hash;
  await page.goto(pathWithHash, { waitUntil: 'load' });

  if (opts?.passphrase) {
    await expect(page.getByText('Passphrase Required')).toBeVisible({
      timeout: 15_000,
    });
    await page.locator('#claim-passphrase').fill(opts.passphrase);
    await page.getByRole('button', { name: 'Decrypt' }).click();
  }

  await expect(page.getByText('Secret Decrypted')).toBeVisible({
    timeout: 15_000,
  });

  // Click the show button to reveal the secret
  await page.getByRole('button', { name: 'Show secret' }).click();

  const content = await page.locator('pre').textContent();
  if (content === null) throw new Error('Secret content not found');
  return content.trim();
}
