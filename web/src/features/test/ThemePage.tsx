import { ThemeToggle } from '../../components/ThemeToggle';
import { Logo } from '../../components/Logo';
import {
  CircleXmarkIcon,
  ClipboardIcon,
  FireIcon,
} from '../../components/Icons';
import { navigate } from '../../router';
import type { ComponentChildren } from 'preact';

/* ── Helpers ───────────────────────────────────────────────── */

function Section({
  title,
  children,
}: {
  title: string;
  children: ComponentChildren;
}) {
  return (
    <section class="space-y-4">
      <h2 class="heading">{title}</h2>
      {children}
    </section>
  );
}

function Swatch({
  bg,
  label,
  dark,
}: {
  bg: string;
  label: string;
  dark?: boolean;
}) {
  return (
    <div class="flex flex-col items-center gap-1">
      <div
        class={`h-10 w-full rounded-lg border border-border ${bg}`}
        title={label}
      />
      <span class={`text-xs ${dark ? 'text-faint' : 'text-muted'}`}>
        {label}
      </span>
    </div>
  );
}

/* ── Swatch data (only shades used in real pages) ─────────── */

const greensUsed = [
  { bg: 'bg-green-500', label: '500' },
  { bg: 'bg-green-950', label: '950' },
];

const neutralsUsed = [
  { bg: 'bg-neutral-200', label: '200' },
  { bg: 'bg-neutral-700', label: '700', dark: true },
  { bg: 'bg-neutral-800', label: '800', dark: true },
  { bg: 'bg-neutral-900', label: '900', dark: true },
];

const semantics = [
  { bg: 'bg-surface', label: 'surface' },
  { bg: 'bg-surface-raised', label: 'raised' },
  { bg: 'bg-accent', label: 'accent' },
  { bg: 'bg-error', label: 'error' },
];

/* ── Page ──────────────────────────────────────────────────── */

export function ThemePage() {
  return (
    <div class="min-h-screen px-6 py-10 text-text">
      <div class="mx-auto space-y-10">
        {/* Header */}
        <div class="flex items-center justify-between">
          <div>
            <h1 class="text-lg font-bold tracking-wide">Theme Test</h1>
            <p class="text-muted">
              Design token reference &middot;{' '}
              <a
                href="/"
                onClick={(e: MouseEvent) => {
                  e.preventDefault();
                  navigate('/');
                }}
              >
                Back to app
              </a>
            </p>
          </div>
          <ThemeToggle />
        </div>

        {/* Logo */}
        <Section title="Logo Variants">
          <div class="flex items-center gap-8">
            <div class="light rounded-lg border border-white bg-white p-4 shadow-lg">
              <Logo />

              <div class="mt-1 text-center text-xs text-muted">
                Light Theme Logo
              </div>
            </div>
            <div class="dark rounded-lg border-border bg-black p-4 shadow-lg">
              <Logo />

              <div class="mt-1 text-center text-xs text-muted">
                Dark Theme Logo
              </div>
            </div>
          </div>
        </Section>

        {/* Green palette (used shades only) */}
        <Section title="Green Palette (used shades)">
          <p class="text-muted">
            Only shades referenced in application code. Full palette (50–950) is
            defined in the theme for semantic tokens.
          </p>
          <div class="grid grid-cols-2 gap-2">
            {greensUsed.map((s) => (
              <Swatch key={s.label} {...s} dark={parseInt(s.label) >= 600} />
            ))}
          </div>
        </Section>

        {/* Neutral palette (used shades only) */}
        <Section title="Neutral Palette (used shades)">
          <div class="grid grid-cols-4 gap-2">
            {neutralsUsed.map((s) => (
              <Swatch key={s.label} {...s} />
            ))}
          </div>
        </Section>

        {/* Semantic tokens */}
        <Section title="Semantic Tokens">
          <div class="grid grid-cols-4 gap-2">
            {semantics.map((s) => (
              <Swatch key={s.label} {...s} />
            ))}
          </div>
        </Section>

        {/* Typography */}
        <Section title="Typography">
          <div class="space-y-3">
            <div class="heading">Section Heading `.heading`</div>
            <p>Body (base) — The quick brown fox jumps over the lazy dog.</p>
            <p class="text-muted">Muted — Secondary information</p>
            <p class="text-faint">Faint — Tertiary information</p>
            <p class="font-mono text-sm">
              Monospace — const secret = "abc123"
            </p>
          </div>
        </Section>

        {/* Buttons */}
        <Section title="Buttons">
          <div class="space-y-4">
            <div class="flex flex-wrap items-center gap-3">
              <button class="btn btn-primary" type="button">
                Primary
              </button>

              <button class="btn btn-primary" type="button" disabled>
                Primary Disabled
              </button>

              <button class="btn" type="button">
                Button
              </button>

              <button class="btn" type="button">
                <ClipboardIcon />
                Icon
              </button>

              <button class="btn btn-danger" type="button">
                <FireIcon />
                Danger
              </button>
            </div>

            <div class="flex flex-wrap items-center gap-3">
              <button class="btn btn-primary btn-sm" type="button">
                Small Primary
              </button>

              <button class="btn btn-sm" type="button">
                Small Secondary
              </button>

              <button class="btn btn-sm flex gap-1.5" type="button">
                <ClipboardIcon class="size-4" />
                Copy
              </button>

              <button class="btn-destructive-subtle" type="button">
                <CircleXmarkIcon class="size-4" />
                Delete
              </button>
            </div>
          </div>
        </Section>

        {/* Links */}
        <Section title="Links">
          <div class="space-y-2">
            <p>
              Inline link:{' '}
              <a class="link" href="#demo">
                default accent link
              </a>{' '}
              within text.
            </p>
            <p class="text-muted">
              Muted context:{' '}
              <a class="link" href="#demo">
                link in muted text
              </a>
              .
            </p>
          </div>
        </Section>

        {/* Cards */}
        <Section title="Cards">
          <div class="grid gap-4 sm:grid-cols-2">
            <div class="card">
              <h3 class="mb-2 font-semibold">Default Card</h3>
              <p class="text-muted">Standard surface with border and shadow.</p>
            </div>
            <div class="card bg-surface-raised shadow-lg">
              <h3 class="mb-2 font-semibold">Raised Card</h3>
              <p class="text-muted">Surface-raised background variant.</p>
            </div>
            <div class="rounded-lg border border-green-600/30 bg-green-50 p-6 dark:border-green-400/20 dark:bg-green-950">
              <h3 class="mb-2 font-semibold text-green-800 dark:text-green-200">
                Success Card
              </h3>
              <p class="text-green-700 dark:text-green-300">
                Using the green palette directly.
              </p>
            </div>
            <div class="rounded-lg border border-error/30 bg-error/5 p-6">
              <h3 class="mb-2 font-semibold text-red-700 dark:text-red-400">
                Error Card
              </h3>
              <p class="text-error">Using the error semantic token.</p>
            </div>
          </div>
        </Section>

        {/* Form inputs */}
        <Section title="Form Controls">
          <div class="space-y-4">
            <div>
              <label class="mb-1 block font-medium">Text Input</label>
              <input
                type="text"
                placeholder="Placeholder text"
                class="input"
              />
            </div>
            <div>
              <label class="mb-1 block font-medium">Disabled Input</label>
              <input
                type="text"
                value="Can't edit this"
                disabled
                class="input"
              />
            </div>
            <div>
              <label class="mb-1 block font-medium">Input with Error</label>
              <input
                type="text"
                value="Bad value"
                class="input input-error"
              />
              <p class="mt-1 text-xs text-error">This field has an error.</p>
            </div>
            <div>
              <label class="mb-1 block font-medium">Textarea</label>
              <textarea
                placeholder="Write something..."
                rows={3}
                class="textarea"
              />
            </div>
          </div>
        </Section>

        {/* Inline code */}
        <Section title="Inline Code">
          <p>
            Secret ID:{' '}
            <code class="code select-all">abc123-def456-ghi789</code>
          </p>
        </Section>

        {/* Shadows */}
        <Section title="Shadows">
          <div class="flex items-center gap-6">
            <div class="flex flex-col items-center gap-1">
              <div class="size-14 rounded-lg bg-surface shadow-sm" />
              <span class="text-xs text-muted">shadow-sm</span>
            </div>
            <div class="flex flex-col items-center gap-1">
              <div class="size-14 rounded-lg bg-surface shadow-md" />
              <span class="text-xs text-muted">shadow-md</span>
            </div>
            <div class="flex flex-col items-center gap-1">
              <div class="size-14 rounded-lg bg-surface shadow-lg" />
              <span class="text-xs text-muted">shadow-lg</span>
            </div>
          </div>
        </Section>

        {/* Footer */}
        <footer class="border-t border-border pt-6 text-center text-xs text-faint">
          Press{' '}
          <kbd class="rounded border border-border bg-surface-raised px-1.5 py-0.5 font-mono">
            D
          </kbd>{' '}
          to toggle dark mode
        </footer>
      </div>
    </div>
  );
}
