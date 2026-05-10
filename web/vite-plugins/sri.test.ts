import { describe, it, expect } from 'vitest';
import { injectIntegrity, sha384Base64, type AssetLookup } from './sri';

describe('sha384Base64', () => {
  it('matches the SHA-384 of an empty string (known vector)', () => {
    // SHA-384("") = 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b
    // (base64-encoded; computed via openssl dgst -sha384 -binary | base64)
    expect(sha384Base64('')).toBe(
      'OLBgp1GsljhM2TJ+sbHjaiH9txEUvgdDTAzHv2P24donTt6/529l+9Ua0vFImLlb',
    );
  });

  it('produces a stable digest for identical strings (Uint8Array vs string)', () => {
    const s = 'console.log(1);';
    const b = new TextEncoder().encode(s);
    expect(sha384Base64(s)).toBe(sha384Base64(b));
  });
});

describe('injectIntegrity', () => {
  const APP_JS = 'console.log("hi");';
  const STYLE_CSS = 'body { color: red; }';
  const lookup: AssetLookup = (key) => {
    if (key === 'assets/app.js') return APP_JS;
    if (key === 'assets/style.css') return STYLE_CSS;
    return null;
  };

  it('adds integrity + crossorigin to a bundle script', () => {
    const html =
      '<script type="module" src="/static/assets/app.js"></script>';
    const out = injectIntegrity(html, '/static/', lookup);
    expect(out).toContain(`integrity="sha384-${sha384Base64(APP_JS)}"`);
    expect(out).toContain('crossorigin="anonymous"');
  });

  it('adds integrity + crossorigin to a stylesheet link', () => {
    const html =
      '<link rel="stylesheet" href="/static/assets/style.css">';
    const out = injectIntegrity(html, '/static/', lookup);
    expect(out).toContain(`integrity="sha384-${sha384Base64(STYLE_CSS)}"`);
    expect(out).toContain('crossorigin="anonymous"');
  });

  it('adds integrity to modulepreload links', () => {
    const html =
      '<link rel="modulepreload" href="/static/assets/app.js">';
    const out = injectIntegrity(html, '/static/', lookup);
    expect(out).toContain(`integrity="sha384-${sha384Base64(APP_JS)}"`);
  });

  it('replaces an existing crossorigin keyword (Vite emits bare `crossorigin`)', () => {
    const html =
      '<script type="module" crossorigin src="/static/assets/app.js"></script>';
    const out = injectIntegrity(html, '/static/', lookup);
    // No duplicate crossorigin attributes.
    expect(out.match(/crossorigin/g)?.length).toBe(1);
    expect(out).toContain('crossorigin="anonymous"');
  });

  it('replaces an existing integrity attribute rather than duplicating', () => {
    const html =
      '<script integrity="sha384-OLD" src="/static/assets/app.js"></script>';
    const out = injectIntegrity(html, '/static/', lookup);
    expect(out.match(/integrity=/g)?.length).toBe(1);
    expect(out).not.toContain('sha384-OLD');
    expect(out).toContain(`integrity="sha384-${sha384Base64(APP_JS)}"`);
  });

  it('leaves non-bundle URLs alone (favicons, manifest)', () => {
    const html =
      '<link rel="icon" href="/static/favicon-dark.svg"><link rel="manifest" href="/static/site.webmanifest">';
    expect(injectIntegrity(html, '/static/', lookup)).toBe(html);
  });

  it('leaves inline scripts alone', () => {
    const html = '<script>(function(){var t=1;})()</script>';
    expect(injectIntegrity(html, '/static/', lookup)).toBe(html);
  });

  it('leaves absolute URLs alone (we never SRI someone else\'s CDN)', () => {
    const html =
      '<script src="https://cdn.example.com/x.js"></script>';
    expect(injectIntegrity(html, '/static/', lookup)).toBe(html);
  });

  it('leaves protocol-relative URLs alone', () => {
    const html = '<script src="//cdn.example.com/x.js"></script>';
    expect(injectIntegrity(html, '/static/', lookup)).toBe(html);
  });

  it('leaves URLs whose asset is missing from the bundle alone', () => {
    const html =
      '<script src="/static/assets/missing.js"></script>';
    expect(injectIntegrity(html, '/static/', lookup)).toBe(html);
  });

  it('handles a "/" base (dev-style, no /static/ prefix)', () => {
    const html = '<script src="/assets/app.js"></script>';
    const out = injectIntegrity(html, '/', lookup);
    expect(out).toContain(`integrity="sha384-${sha384Base64(APP_JS)}"`);
  });

  it('preserves other attributes on the tag', () => {
    const html =
      '<script type="module" defer src="/static/assets/app.js"></script>';
    const out = injectIntegrity(html, '/static/', lookup);
    expect(out).toContain('type="module"');
    expect(out).toContain('defer');
    expect(out).toContain('integrity="sha384-');
  });

  it('does not touch <link rel="icon"> even if href points at the bundle', () => {
    const html =
      '<link rel="icon" href="/static/assets/style.css">';
    expect(injectIntegrity(html, '/static/', lookup)).toBe(html);
  });
});
