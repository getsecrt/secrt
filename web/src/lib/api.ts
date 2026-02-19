import type {
  ApiInfo,
  CreateRequest,
  CreateResponse,
  ClaimRequest,
  ClaimResponse,
  PasskeyRegisterStartRequest,
  PasskeyRegisterFinishRequest,
  PasskeyLoginStartRequest,
  PasskeyLoginFinishRequest,
  ChallengeResponse,
  AuthFinishResponse,
  SessionResponse,
  ListSecretsResponse,
  ListApiKeysResponse,
  DeleteAccountResponse,
  SecretsCheckResponse,
  AmkWrapper,
  EncMetaV1,
} from '../types';

type ApiErrorBody = { error?: string };

async function readApiError(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as ApiErrorBody;
    if (body.error?.trim()) return body.error;
  } catch {
    /* ignored */
  }
  return `${res.status} ${res.statusText}`;
}

async function requestJson<T>(
  path: string,
  init: RequestInit,
  signal?: AbortSignal,
): Promise<T> {
  const headers = new Headers(init.headers ?? {});
  headers.set('accept', 'application/json');

  const res = await fetch(path, {
    ...init,
    headers,
    credentials: 'same-origin',
    signal,
  });

  if (!res.ok) throw new Error(await readApiError(res));
  return (await res.json()) as T;
}

export async function fetchInfo(signal?: AbortSignal): Promise<ApiInfo> {
  return requestJson<ApiInfo>('/api/v1/info', { method: 'GET' }, signal);
}

export async function createSecret(
  req: CreateRequest,
  apiKey?: string,
  signal?: AbortSignal,
): Promise<CreateResponse> {
  const path = apiKey ? '/api/v1/secrets' : '/api/v1/public/secrets';
  const headers: Record<string, string> = {
    'content-type': 'application/json',
  };
  if (apiKey) headers['authorization'] = `Bearer ${apiKey}`;

  return requestJson<CreateResponse>(
    path,
    { method: 'POST', headers, body: JSON.stringify(req) },
    signal,
  );
}

export async function claimSecret(
  id: string,
  req: ClaimRequest,
  signal?: AbortSignal,
): Promise<ClaimResponse> {
  return requestJson<ClaimResponse>(
    `/api/v1/secrets/${encodeURIComponent(id)}/claim`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(req),
    },
    signal,
  );
}

export async function burnSecret(
  id: string,
  req: ClaimRequest,
  signal?: AbortSignal,
): Promise<void> {
  await requestJson<{ ok: boolean }>(
    `/api/v1/secrets/${encodeURIComponent(id)}/burn`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(req),
    },
    signal,
  );
}

/* ── Auth API ─────────────────────────────────────────── */

export async function registerPasskeyStart(
  req: PasskeyRegisterStartRequest,
  signal?: AbortSignal,
): Promise<ChallengeResponse> {
  return requestJson<ChallengeResponse>(
    '/api/v1/auth/passkeys/register/start',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(req),
    },
    signal,
  );
}

export async function registerPasskeyFinish(
  req: PasskeyRegisterFinishRequest,
  signal?: AbortSignal,
): Promise<AuthFinishResponse> {
  return requestJson<AuthFinishResponse>(
    '/api/v1/auth/passkeys/register/finish',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(req),
    },
    signal,
  );
}

export async function loginPasskeyStart(
  req: PasskeyLoginStartRequest,
  signal?: AbortSignal,
): Promise<ChallengeResponse> {
  return requestJson<ChallengeResponse>(
    '/api/v1/auth/passkeys/login/start',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(req),
    },
    signal,
  );
}

export async function loginPasskeyFinish(
  req: PasskeyLoginFinishRequest,
  signal?: AbortSignal,
): Promise<AuthFinishResponse> {
  return requestJson<AuthFinishResponse>(
    '/api/v1/auth/passkeys/login/finish',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(req),
    },
    signal,
  );
}

export async function fetchSession(
  token: string,
  signal?: AbortSignal,
): Promise<SessionResponse> {
  return requestJson<SessionResponse>(
    '/api/v1/auth/session',
    {
      method: 'GET',
      headers: { authorization: `Bearer ${token}` },
    },
    signal,
  );
}

export async function logout(
  token: string,
  signal?: AbortSignal,
): Promise<void> {
  await requestJson<{ ok: boolean }>(
    '/api/v1/auth/logout',
    {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
    },
    signal,
  );
}

/* ── Dashboard API ───────────────────────────────────── */

export async function listSecrets(
  token: string,
  limit = 50,
  offset = 0,
  signal?: AbortSignal,
): Promise<ListSecretsResponse> {
  return requestJson<ListSecretsResponse>(
    `/api/v1/secrets?limit=${limit}&offset=${offset}`,
    {
      method: 'GET',
      headers: { authorization: `Bearer ${token}` },
    },
    signal,
  );
}

export async function checkSecrets(
  token: string,
  signal?: AbortSignal,
): Promise<SecretsCheckResponse> {
  return requestJson<SecretsCheckResponse>(
    '/api/v1/secrets/check',
    {
      method: 'GET',
      headers: { authorization: `Bearer ${token}` },
    },
    signal,
  );
}

export async function burnSecretAuthed(
  token: string,
  id: string,
  signal?: AbortSignal,
): Promise<void> {
  await requestJson<{ ok: boolean }>(
    `/api/v1/secrets/${encodeURIComponent(id)}/burn`,
    {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
    },
    signal,
  );
}

export async function listApiKeys(
  token: string,
  signal?: AbortSignal,
): Promise<ListApiKeysResponse> {
  return requestJson<ListApiKeysResponse>(
    '/api/v1/apikeys',
    {
      method: 'GET',
      headers: { authorization: `Bearer ${token}` },
    },
    signal,
  );
}

export async function revokeApiKey(
  token: string,
  prefix: string,
  signal?: AbortSignal,
): Promise<void> {
  await requestJson<{ ok: boolean }>(
    `/api/v1/apikeys/${encodeURIComponent(prefix)}/revoke`,
    {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` },
    },
    signal,
  );
}

export async function registerApiKey(
  token: string,
  authTokenB64: string,
  signal?: AbortSignal,
): Promise<{ prefix: string; scopes: string }> {
  return requestJson<{ prefix: string; scopes: string }>(
    '/api/v1/apikeys/register',
    {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ auth_token: authTokenB64 }),
    },
    signal,
  );
}

/* ── Device Auth API ─────────────────────────────────── */

export async function deviceApprove(
  token: string,
  userCode: string,
  amkTransfer?: { ct: string; nonce: string; ecdh_public_key: string },
  signal?: AbortSignal,
): Promise<{ ok: boolean }> {
  const body: Record<string, unknown> = { user_code: userCode };
  if (amkTransfer) body.amk_transfer = amkTransfer;
  return requestJson<{ ok: boolean }>(
    '/api/v1/auth/device/approve',
    {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
    },
    signal,
  );
}

export async function deleteAccount(
  token: string,
  signal?: AbortSignal,
): Promise<DeleteAccountResponse> {
  return requestJson<DeleteAccountResponse>(
    '/api/v1/auth/account',
    {
      method: 'DELETE',
      headers: { authorization: `Bearer ${token}` },
    },
    signal,
  );
}

/* ── AMK Wrapper API ───────────────────────────────── */

export async function upsertAmkWrapper(
  token: string,
  body: {
    key_prefix: string;
    wrapped_amk: string;
    nonce: string;
    amk_commit: string;
    version: number;
  },
  signal?: AbortSignal,
): Promise<{ ok: boolean }> {
  return requestJson<{ ok: boolean }>(
    '/api/v1/amk/wrapper',
    {
      method: 'PUT',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
    },
    signal,
  );
}

export async function getAmkWrapper(
  token: string,
  keyPrefix: string,
  signal?: AbortSignal,
): Promise<AmkWrapper> {
  return requestJson<AmkWrapper>(
    `/api/v1/amk/wrapper?key_prefix=${encodeURIComponent(keyPrefix)}`,
    {
      method: 'GET',
      headers: { authorization: `Bearer ${token}` },
    },
    signal,
  );
}

export async function amkExists(
  token: string,
  signal?: AbortSignal,
): Promise<{ exists: boolean }> {
  return requestJson<{ exists: boolean }>(
    '/api/v1/amk/exists',
    {
      method: 'GET',
      headers: { authorization: `Bearer ${token}` },
    },
    signal,
  );
}

/* ── Encrypted Metadata API ──────────────────────── */

export async function updateSecretMeta(
  token: string,
  secretId: string,
  encMeta: EncMetaV1,
  metaKeyVersion: number,
  signal?: AbortSignal,
): Promise<{ ok: boolean }> {
  return requestJson<{ ok: boolean }>(
    `/api/v1/secrets/${encodeURIComponent(secretId)}/meta`,
    {
      method: 'PUT',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ enc_meta: encMeta, meta_key_version: metaKeyVersion }),
    },
    signal,
  );
}

/* ── Device Auth Challenge API ───────────────────── */

export async function getDeviceChallenge(
  token: string,
  userCode: string,
  signal?: AbortSignal,
): Promise<{ user_code: string; ecdh_public_key?: string; status: string }> {
  return requestJson<{ user_code: string; ecdh_public_key?: string; status: string }>(
    `/api/v1/auth/device/challenge?user_code=${encodeURIComponent(userCode)}`,
    {
      method: 'GET',
      headers: { authorization: `Bearer ${token}` },
    },
    signal,
  );
}
