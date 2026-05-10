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
  return import.meta.env.DEV ? '' : PRIMARY_OFFICIAL_ORIGIN;
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
 * The primary official origin — used as the production fallback for
 * Tauri builds (which load from local files and have no meaningful
 * window.location.origin). Derived from `KNOWN_INSTANCES[0]`; the spec
 * vector test pins this to `spec/v1/instances.json`'s first entry so
 * the apex list and the Tauri fallback never drift.
 */
export const PRIMARY_OFFICIAL_ORIGIN = `https://${KNOWN_INSTANCES[0]}`;

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
 * WHATWG. IPv6 hosts are returned bracket-stripped and lowercased.
 */
export function normalizeHost(host: string): string {
  let h = host.toLowerCase();
  // Strip IPv6 brackets if present (URL.hostname for IPv6 is `[::1]`).
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
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

/** Typed verdict on whether a base URL is trustworthy. Mirrors the Rust
 *  `secrt_core::TrustDecision` enum — same inputs MUST produce the same
 *  verdict in both implementations (enforced by spec-vector tests).
 */
export type TrustDecision =
  | { kind: 'official'; apex: string }
  | { kind: 'trustedCustom' }
  | { kind: 'devLocal' }
  | { kind: 'untrusted' };

/**
 * Normalize a base URL to its origin string (`scheme://host[:port]`).
 * Returns `null` if parsing fails or the URL has no host. Uses the
 * platform `URL` API so IPv6 brackets and ports survive correctly.
 */
export function normalizeOrigin(baseUrl: string): string | null {
  let u: URL;
  try {
    u = new URL(baseUrl);
  } catch {
    return null;
  }
  if (!u.hostname) return null;
  const scheme = u.protocol.slice(0, -1).toLowerCase();
  const host = u.hostname.toLowerCase();
  // Re-bracket IPv6 hosts (URL.hostname strips them on some engines).
  const hostFmt = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  return u.port ? `${scheme}://${hostFmt}:${u.port}` : `${scheme}://${hostFmt}`;
}

function isDevLocalHost(host: string): boolean {
  if (!host) return false;
  const h = host.toLowerCase();
  if (h === 'localhost' || h.endsWith('.local')) return true;
  // IPv4 127.0.0.0/8.
  if (/^127\.\d+\.\d+\.\d+$/.test(h)) return true;
  // IPv6 loopback (URL.hostname returns `[::1]` on some engines, `::1` on others).
  const stripped = h.startsWith('[') && h.endsWith(']') ? h.slice(1, -1) : h;
  if (stripped === '::1' || stripped === '0:0:0:0:0:0:0:1') return true;
  return false;
}

/**
 * Compute the trust verdict for a base URL against the official list
 * and a caller-provided list of user-trusted hosts. Mirrors the Rust
 * implementation in `secrt_core::classify_origin`.
 *
 * Rules:
 *   - Returns `untrusted` if the URL fails to parse or uses anything
 *     other than http/https.
 *   - `official` requires `https`, default port (no explicit port), and
 *     a host that equals or is a strict subdomain of an entry in
 *     `KNOWN_INSTANCES`. Non-default ports force opt-in via
 *     `trustedCustom`.
 *   - `devLocal` covers `localhost`, `127.0.0.0/8`, `::1`, and `*.local`.
 *   - `trustedCustom` matches when the host (lowercased) equals an
 *     entry in `trustedCustom`.
 */
export function classifyOrigin(
  baseUrl: string,
  trustedCustom: readonly string[] = [],
): TrustDecision {
  let u: URL;
  try {
    u = new URL(baseUrl);
  } catch {
    return { kind: 'untrusted' };
  }
  const scheme = u.protocol.slice(0, -1).toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') {
    return { kind: 'untrusted' };
  }
  const rawHost = u.hostname;
  if (!rawHost) return { kind: 'untrusted' };
  if (isDevLocalHost(rawHost)) return { kind: 'devLocal' };

  const host = rawHost.toLowerCase();
  if (scheme === 'https' && !u.port) {
    for (const known of KNOWN_INSTANCES) {
      if (host === known || host.endsWith(`.${known}`)) {
        return { kind: 'official', apex: known };
      }
    }
  }
  for (const trusted of trustedCustom) {
    if (host === trusted.toLowerCase()) return { kind: 'trustedCustom' };
  }
  return { kind: 'untrusted' };
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
