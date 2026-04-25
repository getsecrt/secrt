# i18n Readiness Plan — secrt web

Scope: marketing/homepage UI, navigation, in-app copy. **Not** the whitepaper, privacy docs, or the CLI. Target locales: `en` (source), `fr` (with optional `fr-CA` lean), `is`.

## 1. Pick a library before extracting strings

Three viable choices for Preact + Vite:

| Library | Verdict for secrt |
|---|---|
| **`@lingui/core` + `@lingui/macro`** | **Recommended.** Tiny runtime, ICU MessageFormat, compile-time extraction via Babel macro, .po file output (Fiverr-friendly), Preact-compatible. |
| `react-intl` / `format-js` | Solid but heavier. Overkill for a homepage. |
| Hand-rolled `t()` + JSON | Tempting. Don't. You will regret it the moment Icelandic plural rules show up. |

`.po` files are the lingua franca on Fiverr/Upwork — translators have tools (Poedit, Crowdin) for them. JSON is fine but less universal.

## 2. Extraction discipline — what to wrap

Wrap **anything user-visible**, including:

- Button labels, link text, headings, paragraphs
- `aria-label`, `title`, `alt` attributes (a11y strings are real strings)
- `placeholder` text
- Error messages thrown from `features/*/errors.ts`
- `document.title` and meta description
- TTL labels in `TtlSelector.tsx` (e.g. "1 hour", "24 hours" — these are plural-rule territory)
- Toast/copy-confirmation strings in `CopyButton.tsx`, `ShareResult.tsx`

Do **not** wrap:

- Console logs and dev-only diagnostics
- Crypto error codes / enum keys (translate the *display* of the error, not the code)
- Test fixtures
- URLs, email addresses, brand strings ("secrt", ".is")

## 3. Interpolation — the actual hard part

This is where Icelandic will hurt if you're sloppy.

**Bad:**
```tsx
<p>Sent to {recipientName}</p>
```

**Good:**
```tsx
<Trans>Sent to {recipientName}</Trans>
// or in a string context:
t`Sent to ${recipientName}`
```

The translator sees `"Sent to {recipientName}"` as one unit and can reorder for languages where the verb goes last (e.g. German), or apply case agreement.

**Plurals** must use ICU syntax, not string concatenation:

```tsx
// Bad — breaks in is/ru/pl
`${count} files`

// Good
plural(count, {
  one: '# file',
  other: '# files',
})
```

Icelandic plural rule: `one` for n where `n mod 10 == 1 && n mod 100 != 11`, else `other`. ICU handles this; you just supply the two forms. (Same rule as Russian's `one` form, fwiw.)

## 4. Date / time / number formatting

Use `Intl.DateTimeFormat` and `Intl.NumberFormat` with the active locale, not hardcoded English formats. TTL display ("Expires in 2 hours") should use `Intl.RelativeTimeFormat`.

For Icelandic specifically: thousands separator is `.`, decimal is `,`. `1.234,56` not `1,234.56`. `Intl` handles this if you pass the locale.

## 5. Locale detection + override

Stack:

1. URL prefix (`/fr/...`, `/is/...`) — best for SEO and shareable links
2. Stored preference (localStorage) — overrides browser
3. `navigator.language` — fallback
4. `en` — final fallback

The router (`router.ts`) needs a locale prefix. Add it before extracting strings — retrofitting routing later is painful.

## 6. RTL — not relevant now, but plan for it

You don't need RTL for fr or is. But if you ever add Arabic or Hebrew, `dir="rtl"` cascades from `<html>`. Use logical CSS properties (`margin-inline-start`, not `margin-left`) where you can. Tailwind v4 supports these; cheap insurance.

## 7. The `.is` reputation tax

Errors in Icelandic UI on a `.is` site will be visible to exactly the audience whose trust matters most. Budget for one round of native-speaker review *after* draft translation, not before. Accept that some strings may need to be rewritten in English to translate cleanly — Icelandic doesn't have great equivalents for some startup jargon ("end-to-end encrypted" is a mouthful in is; "zero-knowledge" doubly so). Easier to simplify the English than to mangle the Icelandic.

## 8. fr-CA decision

For a homepage and menu surface (~50–150 strings), maintaining two French locales is more cost than value. Recommendation:

- Ship a single **`fr`** locale with neutral-to-Quebec lexical choices: *courriel* over *email*, *fichier* (universal), *connexion* (universal), *envoyer* (universal). Nothing distinctively Parisian (avoid *mél*, avoid anglicisms like *uploader*).
- If a Quebec user complains, *then* split into `fr-CA`. Don't pre-split.

This gives 80% of the cultural respect for 50% of the translation budget.

## 9. Refactor order (do not skip)

1. Add the i18n library and locale routing (no strings extracted yet).
2. Extract strings to `en.po` *one feature at a time*, starting with `Layout.tsx` + `Nav.tsx`. Land each as its own PR.
3. Once `en.po` is stable for the marketing surface, generate `fr.po` and `is.po` skeletons.
4. *Then* hand off to translator(s).

Extracting and translating in parallel produces drift. English wording will keep changing during the refactor; you don't want to pay a translator twice.

## 10. Testing

- Snapshot tests already exist (`*.test.tsx`). Add a parallel snapshot pass for `fr` and `is` to catch missing translations.
- Add a "pseudo-locale" build that wraps every string in brackets with accents (`[ŝéńt tö §érvér]`). Reveals two bugs at once: unwrapped strings (no brackets) and overflow (Icelandic strings are typically 30%+ longer than English).
- E2E: at least one Playwright run per locale on the critical paths (send, claim).

## Watch items

- **Pluralization in `TtlSelector`** — TTL options like "5 minutes" / "1 hour" / "24 hours" are the most plural-heavy surface. Audit these first.
- **Password generator UI** — any "your password is X characters long" copy needs plural form.
- **Error messages from `errors.ts`** — these are thrown as strings. Refactor to throw error *codes* and translate at the boundary, not at the throw site.
- **`document.title`** updates per route — make sure the locale-aware title also updates on route change.

---

*Drafted Apr 24, 2026. Revisit before extraction begins.*
