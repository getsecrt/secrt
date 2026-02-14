import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { fetchInfo, createSecret, claimSecret, burnSecret } from './api';
import type {
  ApiInfo,
  CreateRequest,
  CreateResponse,
  ClaimResponse,
  EnvelopeJson,
} from '../types';

/** Minimal valid ApiInfo for test responses. */
const mockApiInfo: ApiInfo = {
  authenticated: false,
  ttl: { default_seconds: 86400, max_seconds: 31536000 },
  limits: {
    public: {
      max_envelope_bytes: 262144,
      max_secrets: 100,
      max_total_bytes: 10485760,
      rate: { requests_per_second: 2, burst: 5 },
    },
    authed: {
      max_envelope_bytes: 1048576,
      max_secrets: 1000,
      max_total_bytes: 104857600,
      rate: { requests_per_second: 10, burst: 20 },
    },
  },
  claim_rate: { requests_per_second: 5, burst: 10 },
};

/** Minimal valid envelope for requests. */
const mockEnvelope: EnvelopeJson = {
  v: 1,
  suite: 'v1-pbkdf2-hkdf-aes256gcm-sealed-payload',
  enc: { alg: 'A256GCM', nonce: 'dGVzdA', ciphertext: 'dGVzdA' },
  kdf: { name: 'none' },
  hkdf: {
    hash: 'SHA-256',
    salt: 'dGVzdA',
    enc_info: 'secrt:v1:enc:sealed-payload',
    claim_info: 'secrt:v1:claim:sealed-payload',
    length: 32,
  },
};

function jsonResponse(body: unknown, status = 200, statusText = 'OK') {
  return new Response(JSON.stringify(body), {
    status,
    statusText,
    headers: { 'content-type': 'application/json' },
  });
}

function errorResponse(
  status: number,
  statusText: string,
  body?: { error?: string },
) {
  return new Response(body ? JSON.stringify(body) : null, {
    status,
    statusText,
    headers: body ? { 'content-type': 'application/json' } : {},
  });
}

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('fetchInfo', () => {
  it('returns parsed ApiInfo on success', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(mockApiInfo));

    const result = await fetchInfo();
    expect(result).toEqual(mockApiInfo);
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/info',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('throws on server error with JSON body', async () => {
    vi.mocked(fetch).mockResolvedValue(
      errorResponse(500, 'Internal Server Error', {
        error: 'database unavailable',
      }),
    );

    await expect(fetchInfo()).rejects.toThrow('database unavailable');
  });

  it('throws with status text when error has no JSON body', async () => {
    vi.mocked(fetch).mockResolvedValue(
      errorResponse(500, 'Internal Server Error'),
    );

    await expect(fetchInfo()).rejects.toThrow('500 Internal Server Error');
  });

  it('throws on network error', async () => {
    vi.mocked(fetch).mockRejectedValue(new TypeError('Failed to fetch'));

    await expect(fetchInfo()).rejects.toThrow('Failed to fetch');
  });

  it('passes signal to fetch', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(mockApiInfo));
    const controller = new AbortController();

    await fetchInfo(controller.signal);
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/info',
      expect.objectContaining({ signal: controller.signal }),
    );
  });
});

describe('createSecret', () => {
  const req: CreateRequest = {
    envelope: mockEnvelope,
    claim_hash: 'test-hash',
    ttl_seconds: 3600,
  };

  const mockResponse: CreateResponse = {
    id: 'secret-123',
    expires_at: '2026-02-15T00:00:00Z',
  };

  it('POSTs to public endpoint without apiKey', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(mockResponse));

    const result = await createSecret(req);
    expect(result).toEqual(mockResponse);
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/public/secrets',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('POSTs to authenticated endpoint with apiKey', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(mockResponse));

    await createSecret(req, 'sk_test_key');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/secrets',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('sets Authorization header when apiKey provided', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(mockResponse));

    await createSecret(req, 'sk_test_key');
    const callArgs = vi.mocked(fetch).mock.calls[0];
    const init = callArgs[1] as RequestInit;
    const headers = new Headers(init.headers);
    expect(headers.get('authorization')).toBe('Bearer sk_test_key');
  });

  it('sets content-type and accept headers', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(mockResponse));

    await createSecret(req);
    const callArgs = vi.mocked(fetch).mock.calls[0];
    const init = callArgs[1] as RequestInit;
    const headers = new Headers(init.headers);
    expect(headers.get('content-type')).toBe('application/json');
    expect(headers.get('accept')).toBe('application/json');
  });

  it('sends correct JSON body', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(mockResponse));

    await createSecret(req);
    const callArgs = vi.mocked(fetch).mock.calls[0];
    const init = callArgs[1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual(req);
  });

  it('throws on error response', async () => {
    vi.mocked(fetch).mockResolvedValue(
      errorResponse(413, 'Payload Too Large', { error: 'envelope too large' }),
    );

    await expect(createSecret(req)).rejects.toThrow('envelope too large');
  });
});

describe('claimSecret', () => {
  const mockClaim: ClaimResponse = {
    envelope: mockEnvelope,
  };

  it('POSTs to correct claim endpoint', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(mockClaim));

    await claimSecret('secret-123', { claim: 'token-abc' });
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/secrets/secret-123/claim',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('URI-encodes the secret ID', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(mockClaim));

    await claimSecret('has spaces&special', { claim: 'token' });
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/secrets/has%20spaces%26special/claim',
      expect.anything(),
    );
  });

  it('returns ClaimResponse with envelope', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(mockClaim));

    const result = await claimSecret('id', { claim: 'token' });
    expect(result.envelope).toEqual(mockEnvelope);
  });

  it('sends claim token in request body', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(mockClaim));

    await claimSecret('id', { claim: 'my-claim-token' });
    const callArgs = vi.mocked(fetch).mock.calls[0];
    const init = callArgs[1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({
      claim: 'my-claim-token',
    });
  });

  it('throws on 404', async () => {
    vi.mocked(fetch).mockResolvedValue(
      errorResponse(404, 'Not Found', { error: 'secret not found or already claimed' }),
    );

    await expect(claimSecret('id', { claim: 'token' })).rejects.toThrow(
      'secret not found or already claimed',
    );
  });
});

describe('burnSecret', () => {
  it('POSTs to correct burn endpoint', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ ok: true }));

    await burnSecret('secret-456', { claim: 'burn-token' });
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/secrets/secret-456/burn',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('URI-encodes the secret ID', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ ok: true }));

    await burnSecret('id/with/slashes', { claim: 'token' });
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/secrets/id%2Fwith%2Fslashes/burn',
      expect.anything(),
    );
  });

  it('resolves on success (void return)', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ ok: true }));

    await expect(
      burnSecret('id', { claim: 'token' }),
    ).resolves.toBeUndefined();
  });

  it('throws on error', async () => {
    vi.mocked(fetch).mockResolvedValue(
      errorResponse(403, 'Forbidden', { error: 'invalid claim token' }),
    );

    await expect(burnSecret('id', { claim: 'bad' })).rejects.toThrow(
      'invalid claim token',
    );
  });

  it('passes signal to fetch', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ ok: true }));
    const controller = new AbortController();

    await burnSecret('id', { claim: 'token' }, controller.signal);
    expect(fetch).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ signal: controller.signal }),
    );
  });
});
