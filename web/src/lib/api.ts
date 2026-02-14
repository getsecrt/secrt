import type {
  ApiInfo,
  CreateRequest,
  CreateResponse,
  ClaimRequest,
  ClaimResponse,
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
