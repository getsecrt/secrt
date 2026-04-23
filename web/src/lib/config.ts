/** True when running inside a Tauri WebView. */
export function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

/**
 * API base URL. Empty string for relative URLs (server-hosted or Vite proxy),
 * full origin for production Tauri builds (loaded from local files, no proxy).
 */
export function getApiBase(): string {
  if (!isTauri()) return '';
  // In dev mode, Vite proxy handles /api → secrt.ca; use relative URLs.
  // In production Tauri builds, there's no proxy — use absolute URL.
  return import.meta.env.DEV ? '' : 'https://secrt.ca';
}

/**
 * Security contact address. Derived from the current host so the same
 * SPA bundle serves any deployment (e.g. secrt.is → security@secrt.is,
 * secrt.ca → security@secrt.ca). The Tauri desktop app — which is loaded
 * from local files and has no meaningful host — falls back to the
 * primary deployment.
 */
export function getSecurityEmail(): string {
  if (isTauri() || typeof window === 'undefined') {
    return 'security@secrt.ca';
  }
  const host = window.location.host.replace(/^www\./, '').split(':')[0];
  return `security@${host || 'secrt.ca'}`;
}

/** Hosting facts shown on the Privacy page. */
export interface Infrastructure {
  /** Hosting provider, e.g. "DigitalOcean". */
  provider: string;
  /** Country where the server runs, e.g. "Canada". */
  country: string;
}

/**
 * Hosting infrastructure for the current deployment. Lets the Privacy
 * page state the truth ("hosted on 1984.hosting in Iceland" vs. "hosted
 * on DigitalOcean in Canada") instead of one hardcoded answer. New
 * deployments only need a row here.
 */
export function getInfrastructure(): Infrastructure {
  const host =
    isTauri() || typeof window === 'undefined'
      ? 'secrt.ca'
      : window.location.host.replace(/^www\./, '').split(':')[0];
  switch (host) {
    case 'secrt.is':
      return { provider: '1984.hosting', country: 'Iceland' };
    case 'secrt.ca':
    default:
      return { provider: 'DigitalOcean', country: 'Canada' };
  }
}
