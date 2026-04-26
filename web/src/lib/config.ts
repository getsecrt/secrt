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
 * Sibling secrt instances we trust enough to redirect/handoff to from the
 * Get-Secret form. Wildcard subdomains (e.g. `team.secrt.is`) are treated
 * as the same instance as the apex — see invariant below.
 *
 * **Wildcard-trust invariant:** every host under one of these apexes
 * (`*.secrt.ca`, `*.secrt.is`) must serve the same backend, same storage,
 * and the same SPA bundle. If we ever introduce per-tenant subdomains or
 * let users register custom subdomains, this assumption — and this
 * allowlist — must change.
 *
 * Keep this list in sync with `getInfrastructure()` below; the two
 * enumerate the same set of hosts.
 */
export const KNOWN_INSTANCES: readonly string[] = ['secrt.ca', 'secrt.is'];

/**
 * Lowercase a host and collapse known-instance subdomains to the apex.
 * Returns:
 *   - `secrt.is` for `secrt.is`, `my.secrt.is`, `foo.bar.secrt.is`, `SECRT.IS`
 *   - `secrt.ca` for `secrt.ca`, `www.secrt.ca`, etc.
 *   - the lowercased host as-is for anything else (`evil.tld`, `localhost`)
 *
 * Suffix-matches against `KNOWN_INSTANCES` on label boundaries (so
 * `foosecrt.is` and `secrt.is.evil.tld` are *not* collapsed and won't
 * pass `isKnownInstance`).
 *
 * Primary callers pass `URL.hostname` which is already port-stripped per
 * WHATWG; the function still tolerates an accidental port suffix.
 */
export function normalizeHost(host: string): string {
  let h = host.toLowerCase();
  // Trim accidental port suffix (defensive — URL.hostname has none).
  const colon = h.indexOf(':');
  if (colon !== -1) h = h.slice(0, colon);
  // Trim trailing FQDN dot.
  if (h.endsWith('.')) h = h.slice(0, -1);
  for (const known of KNOWN_INSTANCES) {
    if (h === known || h.endsWith(`.${known}`)) return known;
  }
  return h;
}

/**
 * True if `host` belongs to a known sibling secrt instance (apex or any
 * wildcard subdomain). Used to gate cross-origin redirect / shell-open
 * actions in the Get-Secret form so a phisher can't bounce users to
 * `secrt.evil.tld`.
 */
export function isKnownInstance(host: string): boolean {
  return KNOWN_INSTANCES.includes(normalizeHost(host));
}

/**
 * The canonical host for the current deployment. The Tauri desktop app —
 * loaded from local files and lacking a meaningful host — falls back to
 * the primary deployment.
 */
export function getCanonicalHost(): string {
  if (isTauri() || typeof window === 'undefined') {
    return 'secrt.ca';
  }
  const host = window.location.hostname;
  if (!host) return 'secrt.ca';
  return normalizeHost(host);
}

/**
 * Security contact address. Derived from the current host so the same
 * SPA bundle serves any deployment (e.g. secrt.is → security@secrt.is,
 * secrt.ca → security@secrt.ca).
 */
export function getSecurityEmail(): string {
  return `security@${getCanonicalHost()}`;
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
 * deployments add a row here *and* an entry in `KNOWN_INSTANCES` above.
 */
export function getInfrastructure(): Infrastructure {
  switch (getCanonicalHost()) {
    case 'secrt.is':
      return { provider: '1984.hosting', country: 'Iceland' };
    case 'secrt.ca':
    default:
      return { provider: 'DigitalOcean', country: 'Canada' };
  }
}
