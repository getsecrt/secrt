import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { base64urlEncode } from '../crypto/encoding';
import {
  supportsWebAuthn,
  createPasskeyCredential,
  getPasskeyCredential,
  generateUserId,
} from './webauthn';

describe('supportsWebAuthn', () => {
  it('returns true when PublicKeyCredential exists', () => {
    // happy-dom has window but not PublicKeyCredential
    vi.stubGlobal('PublicKeyCredential', class {});
    expect(supportsWebAuthn()).toBe(true);
    vi.unstubAllGlobals();
  });

  it('returns false when PublicKeyCredential is undefined', () => {
    const original = window.PublicKeyCredential;
    // @ts-expect-error: testing undefined
    delete window.PublicKeyCredential;
    expect(supportsWebAuthn()).toBe(false);
    if (original) window.PublicKeyCredential = original;
  });
});

describe('createPasskeyCredential', () => {
  const fakeRawId = new Uint8Array([1, 2, 3, 4]);
  const fakePublicKey = new Uint8Array([10, 20, 30]);

  beforeEach(() => {
    vi.stubGlobal('PublicKeyCredential', class {});
    const mockCreate = vi.fn().mockResolvedValue({
      rawId: fakeRawId.buffer,
      response: {
        getPublicKey: () => fakePublicKey.buffer,
      },
    });
    vi.stubGlobal('navigator', {
      ...navigator,
      credentials: { create: mockCreate },
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('returns base64url credential ID and public key', async () => {
    const result = await createPasskeyCredential(
      base64urlEncode(new Uint8Array([99])),
      base64urlEncode(new Uint8Array([1])),
      'user@test.com',
      'Test User',
    );
    expect(result.credentialId).toBe(base64urlEncode(fakeRawId));
    expect(result.publicKey).toBe(base64urlEncode(fakePublicKey));
  });

  it('throws when create returns null', async () => {
    vi.stubGlobal('navigator', {
      ...navigator,
      credentials: { create: vi.fn().mockResolvedValue(null) },
    });
    await expect(
      createPasskeyCredential('Y2hhbA', 'dXNlcg', 'u', 'U'),
    ).rejects.toThrow('Credential creation returned null');
  });

  it('throws when getPublicKey is missing', async () => {
    vi.stubGlobal('navigator', {
      ...navigator,
      credentials: {
        create: vi.fn().mockResolvedValue({
          rawId: fakeRawId.buffer,
          response: { getPublicKey: undefined },
        }),
      },
    });
    await expect(
      createPasskeyCredential('Y2hhbA', 'dXNlcg', 'u', 'U'),
    ).rejects.toThrow('No public key');
  });
});

describe('getPasskeyCredential', () => {
  const fakeRawId = new Uint8Array([5, 6, 7]);

  beforeEach(() => {
    vi.stubGlobal('navigator', {
      ...navigator,
      credentials: {
        get: vi.fn().mockResolvedValue({ rawId: fakeRawId.buffer }),
      },
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('returns base64url credential ID', async () => {
    const result = await getPasskeyCredential('Y2hhbGxlbmdl');
    expect(result.credentialId).toBe(base64urlEncode(fakeRawId));
  });

  it('throws when get returns null', async () => {
    vi.stubGlobal('navigator', {
      ...navigator,
      credentials: { get: vi.fn().mockResolvedValue(null) },
    });
    await expect(getPasskeyCredential('Y2hhbA')).rejects.toThrow(
      'Credential assertion returned null',
    );
  });
});

describe('generateUserId', () => {
  it('returns a non-empty base64url string', () => {
    const id = generateUserId();
    expect(id.length).toBeGreaterThan(0);
    // base64url: only these chars
    expect(id).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('returns different values on each call', () => {
    const a = generateUserId();
    const b = generateUserId();
    expect(a).not.toBe(b);
  });
});
