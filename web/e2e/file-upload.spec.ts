import { test, expect } from '@playwright/test';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

test.describe('File upload flow', () => {
  let tempDir: string;

  test.beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'secrt-e2e-'));
  });

  test.afterAll(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  test('file send and claim round-trip', async ({ page, context }) => {
    const filename = 'test-secret.txt';
    const fileContent = `secret file content ${Date.now()}`;
    const filePath = join(tempDir, filename);
    writeFileSync(filePath, fileContent);

    // Navigate to home page
    await page.goto('/');

    // Click to open file chooser and upload
    const fileChooserPromise = page.waitForEvent('filechooser');
    await page.getByText('Choose a file').click();
    const fileChooser = await fileChooserPromise;
    await fileChooser.setFiles(filePath);

    // Should show file name
    await expect(page.getByText(filename)).toBeVisible();

    // Create the secret
    await page.getByRole('button', { name: 'Create secret' }).click();
    await expect(page.getByText('Secret created')).toBeVisible({
      timeout: 15_000,
    });

    const urlBox = page.getByRole('textbox', { name: 'Share URL' });
    const shareUrl = await urlBox.textContent();
    expect(shareUrl).toBeTruthy();

    // Parse URL for claiming
    const parsed = new URL(shareUrl!);
    const pathWithHash = parsed.pathname + parsed.hash;

    // Claim on a new page
    const claimPage = await context.newPage();
    await claimPage.goto(pathWithHash);

    await expect(claimPage.getByText('Secret Decrypted')).toBeVisible({
      timeout: 15_000,
    });

    // Should show file info
    await expect(claimPage.getByText(filename)).toBeVisible();

    // Download button should be visible
    await expect(
      claimPage.getByRole('button', { name: 'Download file' }),
    ).toBeVisible();

    await claimPage.close();
  });
});
