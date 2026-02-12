export type ApiInfo = {
  authenticated: boolean;
  ttl: {
    default_seconds: number;
    max_seconds: number;
  };
};

export async function fetchInfo(signal?: AbortSignal): Promise<ApiInfo> {
  const res = await fetch('/api/v1/info', {
    method: 'GET',
    credentials: 'same-origin',
    signal,
    headers: {
      accept: 'application/json'
    }
  });

  if (!res.ok) {
    throw new Error(`GET /api/v1/info failed (${res.status})`);
  }

  return (await res.json()) as ApiInfo;
}
