import type { Plugin } from 'vite';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Subresource Integrity (SRI) injection for the production bundle.
 *
 * Hand-rolled — no community plugin — to keep supply-chain risk low for
 * a security-critical feature. The plugin walks the emitted bundle,
 * hashes each referenced asset with SHA-384, and rewrites
 * `dist/index.html` to add `integrity="sha384-<base64>"` and
 * `crossorigin="anonymous"` on every external `<script src>` and
 * `<link rel="stylesheet"|"modulepreload">`.
 *
 * **Threat model:** SRI defends against asset tampering when the HTML
 * itself is trusted — CDN compromise, partial server compromise where
 * `dist/assets/*.js` is overwritten but `index.html` isn't, or a
 * compromised proxy modifying JS in flight. It is NOT a rogue-instance
 * defense: a malicious server controls `index.html` and can simply
 * remove the `integrity=` attribute. Cross-host bundle pinning
 * (reproducible builds + signed manifest) is a separate, larger task.
 *
 * Disabled in `mode === 'development'` because Vite's HMR injects
 * scripts dynamically and computing integrity on transient dev assets
 * has no value.
 */

/**
 * Compute the SHA-384 base64 digest of a chunk — the value used in
 * `integrity="sha384-<base64>"` per the W3C SRI spec.
 */
export function sha384Base64(content: Uint8Array | string): string {
  const hash = createHash('sha384');
  hash.update(typeof content === 'string' ? content : Buffer.from(content));
  return hash.digest('base64');
}

/**
 * Look up the source bytes/string of an emitted asset by its bundle
 * key (e.g. `"assets/index-abc.js"`). Returns null when the asset
 * isn't part of the bundle — those references (favicons, manifest,
 * static-copy files from `public/`) are intentionally skipped: SRI
 * doesn't apply to non-script/non-stylesheet resources, and skipping
 * unknown URLs prevents the plugin from breaking on edge cases.
 */
export type AssetLookup = (
  bundleKey: string,
) => Uint8Array | string | null;

/**
 * Pure transformation: take an HTML string, the build's `base` URL,
 * and an asset lookup, and return the same HTML with `integrity` and
 * `crossorigin` injected on every SRI-eligible tag. Exposed for unit
 * testing — the Vite plugin below is a thin shell around this.
 */
export function injectIntegrity(
  html: string,
  base: string,
  lookup: AssetLookup,
): string {
  const tagPattern =
    /<(script|link)\b([^>]*?)\s(src|href)="([^"]+)"([^>]*?)>/gi;
  return html.replace(tagPattern, (full, tag, before, attr, url, after) => {
    const tagLower = tag.toLowerCase();
    if (tagLower === 'link') {
      const rel = matchAttr(`${before} ${after}`, 'rel');
      if (rel !== 'stylesheet' && rel !== 'modulepreload') return full;
    }
    const bundleKey = stripBase(url, base);
    if (bundleKey === null) return full;
    const source = lookup(bundleKey);
    if (source == null) return full;
    const digest = sha384Base64(source);
    const cleanedBefore = stripIntegrityCrossorigin(before);
    const cleanedAfter = stripIntegrityCrossorigin(after);
    return `<${tag}${cleanedBefore} ${attr}="${url}"${cleanedAfter} integrity="sha384-${digest}" crossorigin="anonymous">`;
  });
}

function matchAttr(attrString: string, name: string): string | null {
  const re = new RegExp(`\\b${name}\\s*=\\s*"([^"]+)"`, 'i');
  const m = attrString.match(re);
  return m ? m[1].toLowerCase() : null;
}

function stripIntegrityCrossorigin(s: string): string {
  return s
    .replace(/\s+integrity\s*=\s*"[^"]*"/gi, '')
    .replace(/\s+crossorigin(\s*=\s*"[^"]*")?/gi, '');
}

function stripBase(url: string, base: string): string | null {
  // Skip absolute and protocol-relative URLs — SRI only makes sense for
  // assets we ourselves emit, which Vite always references with the
  // configured `base` prefix.
  if (/^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith('//')) return null;
  const normalized = base.endsWith('/') ? base : `${base}/`;
  if (url.startsWith(normalized)) return url.slice(normalized.length);
  if (normalized === '/' && url.startsWith('/')) return url.slice(1);
  return null;
}

/** Vite plugin entry point.
 *
 * Runs in `closeBundle` (after Vite has written all files) and rewrites
 * `<outDir>/index.html` in place. Reading hashes from disk is the only
 * way to guarantee the integrity values match the bytes the browser
 * will actually fetch — `bundle.chunk.code` in earlier hooks doesn't
 * always equal the final written bytes (Vite post-processes asset
 * references and may add trailing newlines or sourcemap markers
 * between chunk generation and write).
 */
export default function sri(): Plugin {
  let resolvedBase = '/';
  let outDir = 'dist';
  return {
    name: 'secrt-sri',
    apply: 'build',
    configResolved(config) {
      resolvedBase = config.base;
      outDir = config.build.outDir;
    },
    closeBundle() {
      const indexPath = resolve(outDir, 'index.html');
      let html: string;
      try {
        html = readFileSync(indexPath, 'utf-8');
      } catch {
        return; // no index.html — nothing to rewrite
      }
      const lookup: AssetLookup = (key) => {
        try {
          return readFileSync(resolve(outDir, key));
        } catch {
          return null;
        }
      };
      const out = injectIntegrity(html, resolvedBase, lookup);
      if (out !== html) writeFileSync(indexPath, out);
    },
  };
}
