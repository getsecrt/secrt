import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Integration test: confirms `dist/index.html` is real and that every
 * SRI-eligible tag's `integrity` attribute matches the SHA-384 of the
 * referenced file on disk.
 *
 * Gated behind `SRI_VERIFY_BUILD=1` because:
 *   - vanilla `pnpm test` does not run `vite build`, so without a build
 *     the test would either skip or read a stale fixture.
 *   - CI runs `pnpm build` immediately before this test in the
 *     dedicated SRI step.
 *
 * Local: `cd web && pnpm build && SRI_VERIFY_BUILD=1 pnpm test`
 */

const ENABLED = process.env.SRI_VERIFY_BUILD === '1';
const suite = ENABLED ? describe : describe.skip;

suite('SRI on real production build (gated by SRI_VERIFY_BUILD=1)', () => {
  const distDir = resolve(__dirname, '..', 'dist');
  const indexPath = resolve(distDir, 'index.html');

  it('dist/index.html exists and is non-empty', () => {
    const html = readFileSync(indexPath, 'utf-8');
    expect(html.length).toBeGreaterThan(100);
  });

  it('every external bundle script/link carries a matching SHA-384 integrity', () => {
    const html = readFileSync(indexPath, 'utf-8');
    const tagPattern = /<(script|link)\b([^>]*)>/gi;
    let checked = 0;
    let m: RegExpExecArray | null;
    while ((m = tagPattern.exec(html)) !== null) {
      const [, tagRaw, attrs] = m;
      const tag = tagRaw.toLowerCase();
      const url = attrFromString(attrs, tag === 'script' ? 'src' : 'href');
      if (!url) continue; // inline <script>
      // Skip absolute / protocol-relative — never SRI-eligible.
      if (/^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith('//')) continue;
      if (tag === 'link') {
        const rel = attrFromString(attrs, 'rel');
        if (rel !== 'stylesheet' && rel !== 'modulepreload') continue;
      }
      // Resolve URL to a path relative to dist/. The build emits with
      // `base = '/static/'` in production.
      const filePath = resolve(distDir, url.replace(/^\/static\//, ''));
      const bytes = readFileSync(filePath);
      const expected = `sha384-${createHash('sha384')
        .update(bytes)
        .digest('base64')}`;

      const integrity = attrFromString(attrs, 'integrity');
      expect(
        integrity,
        `<${tag}> for ${url} is missing integrity attribute`,
      ).toBeDefined();
      expect(integrity, `integrity mismatch for ${url}`).toBe(expected);

      const crossorigin = attrFromString(attrs, 'crossorigin');
      expect(
        crossorigin,
        `<${tag}> for ${url} is missing crossorigin attribute`,
      ).toBe('anonymous');
      checked++;
    }
    expect(
      checked,
      'no SRI-eligible tags found in dist/index.html — has the build/plugin regressed?',
    ).toBeGreaterThan(0);
  });
});

function attrFromString(attrs: string, name: string): string | null {
  const m = attrs.match(new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`, 'i'));
  if (!m) return null;
  // Lowercase URL-shaped attrs (rel, href, src) so case-insensitive
  // matching works; preserve case for opaque attrs (integrity is
  // base64-with-case, crossorigin is the literal "anonymous").
  if (name === 'rel') return m[1].toLowerCase();
  return m[1];
}
