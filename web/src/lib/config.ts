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
