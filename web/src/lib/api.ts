const ROOT_SALT_LABEL = 'secrt-apikey-v2-root-salt';
const HKDF_AUTH_INFO = 'secrt-auth';
const HKDF_META_INFO = 'secrt-meta-encrypt';

const encoder = new TextEncoder();

export type ApiInfo = {
  authenticated: boolean;
  ttl: {
    default_seconds: number;
    max_seconds: number;
  };
};

export type PasskeyStartResponse = {
  challenge_id: string;
  challenge: string;
  expires_at: string;
};

export type AuthFinishResponse = {
  session_token: string;
  user_id: number;
  handle: string;
  expires_at: string;
};

export type SessionResponse = {
  authenticated: boolean;
  user_id: number | null;
  handle: string | null;
  expires_at: string | null;
};

export type RegisterApiKeyResponse = {
  prefix: string;
  created_at: string;
};

type ApiErrorBody = {
  error?: string;
};

export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlToBytes(value: string): Uint8Array {
  const padded = value + '='.repeat((4 - (value.length % 4)) % 4);
  const b64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

async function readApiError(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as ApiErrorBody;
    if (body.error && body.error.trim()) {
      return body.error;
    }
  } catch {
    // ignored
  }
  return `${res.status} ${res.statusText}`;
}

async function requestJson<T>(
  path: string,
  init: RequestInit,
  signal?: AbortSignal
): Promise<T> {
  const headers = new Headers(init.headers ?? {});
  headers.set('accept', 'application/json');

  const res = await fetch(path, {
    ...init,
    headers,
    credentials: 'same-origin',
    signal
  });

  if (!res.ok) {
    throw new Error(await readApiError(res));
  }

  return (await res.json()) as T;
}

export async function fetchInfo(signal?: AbortSignal): Promise<ApiInfo> {
  return requestJson<ApiInfo>(
    '/api/v1/info',
    {
      method: 'GET'
    },
    signal
  );
}

export async function passkeyRegisterStart(
  displayName: string,
  handle?: string
): Promise<PasskeyStartResponse> {
  return requestJson<PasskeyStartResponse>('/api/v1/auth/passkeys/register/start', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ display_name: displayName, handle })
  });
}

export async function passkeyRegisterFinish(
  challengeId: string,
  credentialId: string,
  publicKey: string
): Promise<AuthFinishResponse> {
  return requestJson<AuthFinishResponse>('/api/v1/auth/passkeys/register/finish', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      challenge_id: challengeId,
      credential_id: credentialId,
      public_key: publicKey
    })
  });
}

export async function passkeyLoginStart(credentialId: string): Promise<PasskeyStartResponse> {
  return requestJson<PasskeyStartResponse>('/api/v1/auth/passkeys/login/start', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_id: credentialId })
  });
}

export async function passkeyLoginFinish(
  challengeId: string,
  credentialId: string
): Promise<AuthFinishResponse> {
  return requestJson<AuthFinishResponse>('/api/v1/auth/passkeys/login/finish', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      challenge_id: challengeId,
      credential_id: credentialId
    })
  });
}

export async function fetchSession(sessionToken: string): Promise<SessionResponse> {
  return requestJson<SessionResponse>('/api/v1/auth/session', {
    method: 'GET',
    headers: {
      authorization: `Bearer ${sessionToken}`
    }
  });
}

export async function logout(sessionToken: string): Promise<void> {
  await requestJson<{ ok: boolean }>('/api/v1/auth/logout', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${sessionToken}`
    }
  });
}

export async function registerApiKey(
  sessionToken: string,
  authTokenB64: string
): Promise<RegisterApiKeyResponse> {
  return requestJson<RegisterApiKeyResponse>('/api/v1/apikeys/register', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${sessionToken}`,
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      auth_token: authTokenB64,
      scopes: ''
    })
  });
}

async function rootSaltBytes(): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(ROOT_SALT_LABEL));
  return new Uint8Array(digest);
}

async function hkdfDerive(rootKey: Uint8Array, info: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', rootKey, 'HKDF', false, ['deriveBits']);
  const salt = await rootSaltBytes();
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: encoder.encode(info)
    },
    key,
    256
  );
  return new Uint8Array(bits);
}

export async function deriveAuthAndEncFromRoot(rootKey: Uint8Array): Promise<{
  authToken: Uint8Array;
  encKey: Uint8Array;
}> {
  if (rootKey.length !== 32) {
    throw new Error('root key must be 32 bytes');
  }
  const [authToken, encKey] = await Promise.all([
    hkdfDerive(rootKey, HKDF_AUTH_INFO),
    hkdfDerive(rootKey, HKDF_META_INFO)
  ]);
  return { authToken, encKey };
}

export function generateRootKey(): Uint8Array {
  const root = new Uint8Array(32);
  crypto.getRandomValues(root);
  return root;
}

export function formatLocalApiKey(prefix: string, rootKey: Uint8Array): string {
  return `sk2_${prefix}.${bytesToBase64Url(rootKey)}`;
}
