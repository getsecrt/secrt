import { expect, test } from '@playwright/test';

test.describe('PWA metadata', () => {
  test('manifest exposes install metadata and reachable icons', async ({
    page,
  }) => {
    await page.goto('/');

    const manifestHref = await page
      .locator('link[rel="manifest"]')
      .getAttribute('href');
    expect(manifestHref).toBeTruthy();

    const manifestUrl = new URL(manifestHref!, page.url()).toString();
    const manifestRes = await page.request.get(manifestUrl);
    expect(manifestRes.ok()).toBeTruthy();

    const manifest = await manifestRes.json();
    expect(manifest.name).toBe('secrt');
    expect(manifest.short_name).toBe('secrt');
    expect(manifest.id).toBe('/');
    expect(manifest.start_url).toBe('/');
    expect(manifest.scope).toBe('/');
    expect(manifest.display).toBe('standalone');

    const icons = Array.isArray(manifest.icons) ? manifest.icons : [];
    expect(icons.length).toBeGreaterThan(0);
    const maskableIcon = icons.find(
      (icon: { purpose?: string }) => icon.purpose === 'maskable',
    );
    expect(maskableIcon).toBeTruthy();

    for (const icon of icons) {
      const src = icon?.src;
      if (typeof src !== 'string' || !src.trim()) continue;
      const iconUrl = new URL(src, manifestUrl).toString();
      const iconRes = await page.request.get(iconUrl);
      expect(iconRes.ok()).toBeTruthy();
    }
  });

  test('theme-color and iOS meta tags are present', async ({ page }) => {
    await page.goto('/');

    const lightTheme = page.locator(
      'meta[name="theme-color"][media="(prefers-color-scheme: light)"]',
    );
    await expect(lightTheme).toHaveAttribute('content', '#ffffff');

    const darkTheme = page.locator(
      'meta[name="theme-color"][media="(prefers-color-scheme: dark)"]',
    );
    await expect(darkTheme).toHaveAttribute('content', '#0f1117');

    const capable = page.locator(
      'meta[name="apple-mobile-web-app-capable"]',
    );
    await expect(capable).toHaveAttribute('content', 'yes');
  });

  test('service worker script is present', async ({ page }) => {
    const swRes = await page.request.get('/sw.js');
    expect(swRes.ok()).toBeTruthy();
    expect(swRes.headers()['content-type']).toContain('javascript');

    const swBody = await swRes.text();
    expect(swBody).toContain("addEventListener('fetch'");
  });
});
