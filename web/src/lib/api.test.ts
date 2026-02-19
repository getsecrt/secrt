import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  fetchInfo,
  createSecret,
  claimSecret,
  burnSecret,
  registerPasskeyStart,
  registerPasskeyFinish,
  loginPasskeyStart,
  loginPasskeyFinish,
  fetchSession,
  logout,
  listSecrets,
  checkSecrets,
  burnSecretAuthed,
  listApiKeys,
  revokeApiKey,
  registerApiKey,
  deviceApprove,
  deleteAccount,
} from './api';
import type {
  ApiInfo,
  CreateRequest,
  CreateResponse,
  ClaimResponse,
  ChallengeResponse,
  AuthFinishResponse,
  SessionResponse,
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
  suite: 'v1-argon2id-hkdf-aes256gcm-sealed-payload',
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
      errorResponse(404, 'Not Found', {
        error: 'secret not found or already claimed',
      }),
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

    await expect(burnSecret('id', { claim: 'token' })).resolves.toBeUndefined();
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

describe('dashboard and account endpoints', () => {
  it('listSecrets calls authenticated list endpoint', async () => {
    const payload = { secrets: [], total: 0, limit: 50, offset: 0 };
    vi.mocked(fetch).mockResolvedValue(jsonResponse(payload));

    const result = await listSecrets('uss_tok.secret', 25, 10);
    expect(result).toEqual(payload);
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/secrets?limit=25&offset=10',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('checkSecrets calls checksum endpoint', async () => {
    const payload = { count: 3, checksum: 'abc123' };
    vi.mocked(fetch).mockResolvedValue(jsonResponse(payload));

    const result = await checkSecrets('uss_tok.secret');
    expect(result).toEqual(payload);
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/secrets/check',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('burnSecretAuthed posts with bearer auth', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ ok: true }));

    await burnSecretAuthed('uss_tok.secret', 'id/with/slash');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/secrets/id%2Fwith%2Fslash/burn',
      expect.objectContaining({ method: 'POST' }),
    );
    const init = vi.mocked(fetch).mock.calls[0][1] as RequestInit;
    const headers = new Headers(init.headers);
    expect(headers.get('authorization')).toBe('Bearer uss_tok.secret');
  });

  it('listApiKeys calls API key listing endpoint', async () => {
    const payload = { api_keys: [] };
    vi.mocked(fetch).mockResolvedValue(jsonResponse(payload));

    const result = await listApiKeys('uss_tok.secret');
    expect(result).toEqual(payload);
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/apikeys',
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('revokeApiKey posts to revocation endpoint', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ ok: true }));

    await revokeApiKey('uss_tok.secret', 'abc123');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/apikeys/abc123/revoke',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('registerApiKey posts auth token payload', async () => {
    const payload = { prefix: 'abc123', scopes: 'full' };
    vi.mocked(fetch).mockResolvedValue(jsonResponse(payload));

    const result = await registerApiKey('uss_tok.secret', 'dGVzdA');
    expect(result).toEqual(payload);
    const call = vi.mocked(fetch).mock.calls[0];
    expect(call[0]).toBe('/api/v1/apikeys/register');
    const init = call[1] as RequestInit;
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ auth_token: 'dGVzdA' });
  });

  it('deleteAccount calls account deletion endpoint', async () => {
    const payload = { ok: true, secrets_burned: 2, keys_revoked: 1 };
    vi.mocked(fetch).mockResolvedValue(jsonResponse(payload));

    const result = await deleteAccount('uss_tok.secret');
    expect(result).toEqual(payload);
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/auth/account',
      expect.objectContaining({ method: 'DELETE' }),
    );
  });
});

/* ── Device Auth API ──────────────────────────────────── */

describe('deviceApprove', () => {
  it('POSTs to device approve endpoint with bearer token', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ ok: true }));

    const result = await deviceApprove('uss_tok.secret', 'ABCD-1234');
    expect(result).toEqual({ ok: true });
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/auth/device/approve',
      expect.objectContaining({ method: 'POST' }),
    );
    const init = vi.mocked(fetch).mock.calls[0][1] as RequestInit;
    const headers = new Headers(init.headers);
    expect(headers.get('authorization')).toBe('Bearer uss_tok.secret');
  });

  it('sends user_code in request body', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ ok: true }));

    await deviceApprove('uss_tok.secret', 'WXYZ-5678');
    const init = vi.mocked(fetch).mock.calls[0][1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({
      user_code: 'WXYZ-5678',
    });
  });

  it('throws on error response', async () => {
    vi.mocked(fetch).mockResolvedValue(
      errorResponse(400, 'Bad Request', { error: 'invalid user code' }),
    );

    await expect(
      deviceApprove('uss_tok.secret', 'BAD-CODE'),
    ).rejects.toThrow('invalid user code');
  });

  it('passes signal to fetch', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ ok: true }));
    const controller = new AbortController();

    await deviceApprove('uss_tok.secret', 'ABCD-1234', controller.signal);
    expect(fetch).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ signal: controller.signal }),
    );
  });
});

/* ── Auth API ─────────────────────────────────────────── */

const mockChallenge: ChallengeResponse = {
  challenge_id: 'ch_123',
  challenge: 'Y2hhbGxlbmdl',
  expires_at: '2026-12-31T00:00:00Z',
};

const mockAuthFinish: AuthFinishResponse = {
  session_token: 'uss_abc.secret',
  display_name: 'alice',
  expires_at: '2026-12-31T00:00:00Z',
};

describe('registerPasskeyStart', () => {
  it('POSTs to register/start endpoint', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(mockChallenge));

    const result = await registerPasskeyStart({ display_name: 'Alice' });
    expect(result).toEqual(mockChallenge);
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/auth/passkeys/register/start',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('throws on error', async () => {
    vi.mocked(fetch).mockResolvedValue(
      errorResponse(400, 'Bad Request', { error: 'display_name required' }),
    );

    await expect(registerPasskeyStart({ display_name: '' })).rejects.toThrow(
      'display_name required',
    );
  });
});

describe('registerPasskeyFinish', () => {
  it('POSTs to register/finish endpoint', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(mockAuthFinish));

    const result = await registerPasskeyFinish({
      challenge_id: 'ch_1',
      credential_id: 'cred_1',
      public_key: 'pk_1',
    });
    expect(result).toEqual(mockAuthFinish);
    expect('user_id' in (result as unknown as Record<string, unknown>)).toBe(
      false,
    );
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/auth/passkeys/register/finish',
      expect.objectContaining({ method: 'POST' }),
    );
  });
});

describe('loginPasskeyStart', () => {
  it('POSTs to login/start endpoint', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(mockChallenge));

    const result = await loginPasskeyStart({ credential_id: 'cred_abc' });
    expect(result).toEqual(mockChallenge);
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/auth/passkeys/login/start',
      expect.objectContaining({ method: 'POST' }),
    );
  });
});

describe('loginPasskeyFinish', () => {
  it('POSTs to login/finish endpoint', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(mockAuthFinish));

    const result = await loginPasskeyFinish({
      challenge_id: 'ch_2',
      credential_id: 'cred_xyz',
    });
    expect(result).toEqual(mockAuthFinish);
    expect('user_id' in (result as unknown as Record<string, unknown>)).toBe(
      false,
    );
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/auth/passkeys/login/finish',
      expect.objectContaining({ method: 'POST' }),
    );
  });
});

describe('fetchSession', () => {
  const mockSession: SessionResponse = {
    authenticated: true,
    display_name: 'alice',
    expires_at: '2026-12-31T00:00:00Z',
  };

  it('GETs session endpoint with bearer token', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(mockSession));

    const result = await fetchSession('uss_tok.secret');
    expect(result).toEqual(mockSession);
    expect('user_id' in (result as unknown as Record<string, unknown>)).toBe(
      false,
    );
    const callArgs = vi.mocked(fetch).mock.calls[0];
    const init = callArgs[1] as RequestInit;
    const headers = new Headers(init.headers);
    expect(headers.get('authorization')).toBe('Bearer uss_tok.secret');
  });

  it('throws on 401', async () => {
    vi.mocked(fetch).mockResolvedValue(
      errorResponse(401, 'Unauthorized', { error: 'invalid token' }),
    );

    await expect(fetchSession('bad_tok')).rejects.toThrow('invalid token');
  });
});

describe('logout', () => {
  it('POSTs to logout endpoint with bearer token', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ ok: true }));

    await logout('uss_tok.secret');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/auth/logout',
      expect.objectContaining({ method: 'POST' }),
    );
    const callArgs = vi.mocked(fetch).mock.calls[0];
    const init = callArgs[1] as RequestInit;
    const headers = new Headers(init.headers);
    expect(headers.get('authorization')).toBe('Bearer uss_tok.secret');
  });

  it('resolves on success (void return)', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ ok: true }));

    await expect(logout('tok')).resolves.toBeUndefined();
  });
});
