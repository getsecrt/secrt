import { describe, it, expect } from 'vitest';
import {
  deriveAuthToken,
  generateApiKeyMaterial,
  formatWireApiKey,
} from './apikey';

describe('deriveAuthToken', () => {
  it('produces 32-byte output from 32-byte root key', async () => {
    const rootKey = new Uint8Array(32);
    rootKey.fill(0xab);
    const token = await deriveAuthToken(rootKey);
    expect(token).toBeInstanceOf(Uint8Array);
    expect(token.length).toBe(32);
  });

  it('rejects root key shorter than 32 bytes', async () => {
    const short = new Uint8Array(16);
    await expect(deriveAuthToken(short)).rejects.toThrow(
      'root key must be 32 bytes',
    );
  });

  it('rejects root key longer than 32 bytes', async () => {
    const long = new Uint8Array(64);
    await expect(deriveAuthToken(long)).rejects.toThrow(
      'root key must be 32 bytes',
    );
  });

  it('rejects empty root key', async () => {
    const empty = new Uint8Array(0);
    await expect(deriveAuthToken(empty)).rejects.toThrow(
      'root key must be 32 bytes',
    );
  });

  it('is deterministic for the same root key', async () => {
    const rootKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) rootKey[i] = i;
    const token1 = await deriveAuthToken(rootKey);
    const token2 = await deriveAuthToken(rootKey);
    expect(token1).toEqual(token2);
  });

  it('produces different tokens for different root keys', async () => {
    const rootA = new Uint8Array(32);
    rootA.fill(0x01);
    const rootB = new Uint8Array(32);
    rootB.fill(0x02);
    const tokenA = await deriveAuthToken(rootA);
    const tokenB = await deriveAuthToken(rootB);
    expect(tokenA).not.toEqual(tokenB);
  });
});

describe('generateApiKeyMaterial', () => {
  it('returns rootKey, authToken, and authTokenB64', async () => {
    const material = await generateApiKeyMaterial();
    expect(material).toHaveProperty('rootKey');
    expect(material).toHaveProperty('authToken');
    expect(material).toHaveProperty('authTokenB64');
  });

  it('rootKey is 32 bytes', async () => {
    const { rootKey } = await generateApiKeyMaterial();
    expect(rootKey).toBeInstanceOf(Uint8Array);
    expect(rootKey.length).toBe(32);
  });

  it('authToken is 32 bytes', async () => {
    const { authToken } = await generateApiKeyMaterial();
    expect(authToken).toBeInstanceOf(Uint8Array);
    expect(authToken.length).toBe(32);
  });

  it('authTokenB64 is a valid base64url string (no +, /, or =)', async () => {
    const { authTokenB64 } = await generateApiKeyMaterial();
    expect(authTokenB64).not.toContain('+');
    expect(authTokenB64).not.toContain('/');
    expect(authTokenB64).not.toContain('=');
    expect(authTokenB64.length).toBeGreaterThan(0);
  });

  it('authToken matches deriveAuthToken(rootKey)', async () => {
    const { rootKey, authToken } = await generateApiKeyMaterial();
    const derived = await deriveAuthToken(rootKey);
    expect(authToken).toEqual(derived);
  });

  it('generates unique material on each call', async () => {
    const a = await generateApiKeyMaterial();
    const b = await generateApiKeyMaterial();
    expect(a.rootKey).not.toEqual(b.rootKey);
    expect(a.authToken).not.toEqual(b.authToken);
    expect(a.authTokenB64).not.toBe(b.authTokenB64);
  });
});

describe('formatWireApiKey', () => {
  it('produces ak2_<prefix>.<b64> format', () => {
    const token = new Uint8Array([1, 2, 3, 4]);
    const result = formatWireApiKey('test', token);
    expect(result).toMatch(/^ak2_test\./);
  });

  it('includes base64url-encoded auth token after the dot', () => {
    const token = new Uint8Array([0xff, 0xfe, 0xfd]);
    const result = formatWireApiKey('prod', token);
    const parts = result.split('.');
    expect(parts.length).toBe(2);
    expect(parts[0]).toBe('ak2_prod');
    // base64url of [0xff, 0xfe, 0xfd] = "__79" (no padding)
    expect(parts[1]).toBe('__79');
  });

  it('works with empty prefix', () => {
    const token = new Uint8Array([0x00]);
    const result = formatWireApiKey('', token);
    expect(result).toMatch(/^ak2_\./);
  });

  it('preserves prefix exactly as given', () => {
    const token = new Uint8Array([0x42]);
    expect(formatWireApiKey('sk_live', token)).toMatch(/^ak2_sk_live\./);
  });
});
