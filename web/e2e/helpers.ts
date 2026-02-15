import { type Page, expect } from '@playwright/test';

interface FakePasskeyOptions {
  createId?: string;
  getId?: string;
  publicKeyId?: string;
}

/**
 * Install a deterministic passkey shim before app code runs.
 * This exercises the full frontend/backend auth flow while avoiding
 * dependence on host OS authenticator prompts in CI.
 */
export async function installFakePasskey(
  page: Page,
  opts?: FakePasskeyOptions,
): Promise<void> {
  const createId = opts?.createId ?? 'cred-e2e-default';
  const getId = opts?.getId ?? createId;
  const publicKeyId = opts?.publicKeyId ?? `pk-${createId}`;

  await page.context().addInitScript(
    ({ createId, getId, publicKeyId }) => {
      const enc = new TextEncoder();
      const toArrayBuffer = (value: string) => enc.encode(value).buffer;

      let currentCreateId = createId;
      let currentGetId = getId;
      let currentPublicKeyId = publicKeyId;

      const credentials = Object.create(navigator.credentials ?? {});
      credentials.create = async () => ({
        type: 'public-key',
        rawId: toArrayBuffer(currentCreateId),
        response: {
          getPublicKey: () => toArrayBuffer(currentPublicKeyId),
        },
      });
      credentials.get = async () => ({
        type: 'public-key',
        rawId: toArrayBuffer(currentGetId),
        response: {},
      });

      Object.defineProperty(navigator, 'credentials', {
        configurable: true,
        value: credentials,
      });

      if (typeof (window as any).PublicKeyCredential === 'undefined') {
        (window as any).PublicKeyCredential = class PublicKeyCredential {};
      }

      (window as any).__secrtSetFakePasskeyIds = (next: {
        createId?: string;
        getId?: string;
        publicKeyId?: string;
      }) => {
        if (next.createId) currentCreateId = next.createId;
        if (next.getId) currentGetId = next.getId;
        if (next.publicKeyId) currentPublicKeyId = next.publicKeyId;
      };
    },
    { createId, getId, publicKeyId },
  );
}

export async function setFakePasskeyIds(
  page: Page,
  next: FakePasskeyOptions,
): Promise<void> {
  await page.evaluate((ids) => {
    const fn = (window as any).__secrtSetFakePasskeyIds;
    if (typeof fn === 'function') fn(ids);
  }, next);
}

export async function registerPasskeyAccount(
  page: Page,
  opts?: { displayName?: string },
): Promise<string> {
  const displayName =
    opts?.displayName ??
    `e2e-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;

  await page.goto('/register');
  await page.locator('#display-name').fill(displayName);
  await page.getByRole('button', { name: 'Register with Passkey' }).click();
  await expect(page.getByPlaceholder('Enter your secret...')).toBeVisible({
    timeout: 15_000,
  });

  await expect
    .poll(async () => {
      return page.evaluate(() => localStorage.getItem('session_token'));
    })
    .toMatch(/^uss_/);

  return displayName;
}

export async function loginWithPasskey(page: Page): Promise<void> {
  await page.goto('/login');
  await page.getByRole('button', { name: 'Log in with Passkey' }).click();
  await expect(page.getByPlaceholder('Enter your secret...')).toBeVisible({
    timeout: 15_000,
  });
}

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
  await expect(page.getByText('Secret Created')).toBeVisible({
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

  // Click "View Secret" on the confirm screen to initiate the claim
  await expect(
    page.getByRole('button', { name: 'View Secret' }),
  ).toBeVisible({ timeout: 15_000 });
  await page.getByRole('button', { name: 'View Secret' }).click();

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

  const content = await page.locator('textarea').inputValue();
  if (content === null) throw new Error('Secret content not found');
  return content.trim();
}
