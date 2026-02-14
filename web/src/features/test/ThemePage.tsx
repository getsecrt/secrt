import { ThemeToggle } from '../../components/ThemeToggle';
import { Logo } from '../../components/Logo';
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
        class={`h-12 w-full rounded-lg border border-black/10 ${bg}`}
        title={label}
      />
      <span class={`text-xs ${dark ? 'text-faint' : 'text-muted'}`}>
        {label}
      </span>
    </div>
  );
}

/* ── Swatch data ───────────────────────────────────────────── */

const greens = [
  { bg: 'bg-green-50', label: '50' },
  { bg: 'bg-green-100', label: '100' },
  { bg: 'bg-green-200', label: '200' },
  { bg: 'bg-green-300', label: '300' },
  { bg: 'bg-green-400', label: '400' },
  { bg: 'bg-green-500', label: '500' },
  { bg: 'bg-green-600', label: '600' },
  { bg: 'bg-green-700', label: '700' },
  { bg: 'bg-green-800', label: '800' },
  { bg: 'bg-green-900', label: '900' },
  { bg: 'bg-green-950', label: '950' },
];

const neutrals = [
  { bg: 'bg-neutral-50', label: '50' },
  { bg: 'bg-neutral-100', label: '100' },
  { bg: 'bg-neutral-200', label: '200' },
  { bg: 'bg-neutral-300', label: '300' },
  { bg: 'bg-neutral-400', label: '400' },
  { bg: 'bg-neutral-500', label: '500' },
  { bg: 'bg-neutral-600', label: '600' },
  { bg: 'bg-neutral-700', label: '700' },
  { bg: 'bg-neutral-800', label: '800' },
  { bg: 'bg-neutral-900', label: '900' },
  { bg: 'bg-neutral-950', label: '950' },
];

const semantics = [
  { bg: 'bg-bg', label: 'bg' },
  { bg: 'bg-surface', label: 'surface' },
  { bg: 'bg-surface-raised', label: 'raised' },
  { bg: 'bg-border', label: 'border' },
  { bg: 'bg-accent', label: 'accent' },
  { bg: 'bg-accent-hover', label: 'hover' },
  { bg: 'bg-error', label: 'error' },
  { bg: 'bg-success', label: 'success' },
];

/* ── Page ──────────────────────────────────────────────────── */

export function ThemePage() {
  return (
    <div class="min-h-screen bg-bg px-6 py-10 text-text">
      <div class="mx-auto max-w-3xl space-y-10">
        {/* Header */}
        <div class="flex items-center justify-between">
          <div>
            <h1 class="text-2xl font-bold tracking-wide">Theme Test</h1>
            <p class="text-sm text-muted">
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

        {/* Green palette */}
        <Section title="Green Palette">
          <p class="text-sm text-muted">
            Hue 140–147, chroma peaks at 400, even lightness steps. Utilities:{' '}
            <code class="rounded border border-border/50 bg-surface-raised px-1.5 py-0.5 font-mono text-xs">
              bg-green-500
            </code>{' '}
            <code class="rounded border border-border/50 bg-surface-raised px-1.5 py-0.5 font-mono text-xs">
              text-green-800
            </code>{' '}
            etc.
          </p>
          <div class="grid grid-cols-11 gap-2">
            {greens.map((s) => (
              <Swatch key={s.label} {...s} dark={parseInt(s.label) >= 600} />
            ))}
          </div>
        </Section>

        {/* Neutral palette */}
        <Section title="Neutral Palette (Tailwind default)">
          <div class="grid grid-cols-11 gap-2">
            {neutrals.map((s) => (
              <Swatch key={s.label} {...s} dark={parseInt(s.label) >= 600} />
            ))}
          </div>
        </Section>

        {/* Semantic tokens */}
        <Section title="Semantic Tokens">
          <div class="grid grid-cols-9 gap-2">
            {semantics.map((s) => (
              <Swatch key={s.label} {...s} />
            ))}
          </div>
        </Section>

        {/* Typography */}
        <Section title="Typography">
          <div class="space-y-3">
            <h1 class="text-2xl font-bold tracking-wide">
              Main Page Heading H1
            </h1>
            <div class="heading">Secondary Heading `.heading`</div>
            <p>Body (base) — The quick brown fox jumps over the lazy dog.</p>
            <p class="text-sm">
              Small — The quick brown fox jumps over the lazy dog.
            </p>
            <p class="text-sm text-muted">
              Small / muted — Secondary information
            </p>
            <p class="border-sm text font-mono">
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
              <button class="btn btn-danger" type="button">
                Danger (inline)
              </button>
            </div>
            <div class="flex flex-wrap items-center gap-3">
              <button
                class="btn btn-primary rounded-md px-2 py-1 text-xs"
                type="button"
              >
                Small Primary
              </button>
              <button class="btn px-2 py-1 text-xs" type="button">
                Small Secondary
              </button>
            </div>
          </div>
        </Section>

        {/* Links */}
        <Section title="Links">
          <div class="space-y-2">
            <p>
              Inline link: <a href="#demo">default accent link</a> within text.
            </p>
            <p class="text-sm text-muted">
              Muted context: <a href="#demo">link in muted text</a>.
            </p>
            <div class="flex gap-6 text-sm">
              <a href="#demo">Nav link one</a>
              <a href="#demo">Nav link two</a>
              <a href="#demo">Nav link three</a>
            </div>
          </div>
        </Section>

        {/* Cards */}
        <Section title="Cards">
          <div class="grid gap-4 sm:grid-cols-2">
            <div class="card">
              <h3 class="mb-2 font-semibold">Default Card</h3>
              <p class="text-sm text-muted">
                Standard surface with border and shadow.
              </p>
            </div>
            <div class="card bg-surface-raised">
              <h3 class="mb-2 font-semibold">Raised Card</h3>
              <p class="text-sm text-muted">
                Surface-raised background variant.
              </p>
            </div>
            <div class="rounded-lg border border-green-600/30 bg-green-50 p-6 dark:border-green-400/20 dark:bg-green-950">
              <h3 class="mb-2 font-semibold text-green-800 dark:text-green-200">
                Success Card
              </h3>
              <p class="text-sm text-green-700 dark:text-green-300">
                Using the green palette directly.
              </p>
            </div>
            <div class="rounded-lg border border-error/30 bg-error/5 p-6">
              <h3 class="mb-2 font-semibold text-red-700 dark:text-red-400">
                Error Card
              </h3>
              <p class="text-sm text-error">Using the error semantic token.</p>
            </div>
          </div>
        </Section>

        {/* Form inputs */}
        <Section title="Form Controls">
          <div class="grid gap-6 sm:grid-cols-2">
            <div class="space-y-4">
              <div>
                <label class="mb-1 block text-sm font-medium">Text Input</label>
                <input
                  type="text"
                  placeholder="Placeholder text"
                  class="input"
                />
              </div>
              <div>
                <label class="mb-1 block text-sm font-medium">
                  Disabled Input
                </label>
                <input
                  type="text"
                  value="Can't edit this"
                  disabled
                  class="input"
                />
              </div>
              <div>
                <label class="mb-1 block text-sm font-medium">
                  Input with Error
                </label>
                <input
                  type="text"
                  value="Bad value"
                  class="input input-error"
                />
                <p class="mt-1 text-xs text-error">This field has an error.</p>
              </div>
              <div>
                <label class="mb-1 block text-sm font-medium">Select</label>
                <select class="select">
                  <option>Option one</option>
                  <option>Option two</option>
                  <option>Option three</option>
                </select>
              </div>
            </div>
            <div class="space-y-4">
              <div>
                <label class="mb-1 block text-sm font-medium">Textarea</label>
                <textarea
                  placeholder="Write something..."
                  rows={4}
                  class="textarea"
                />
              </div>
              <div class="space-y-2">
                <label class="mb-1 block text-sm font-medium">Checkboxes</label>
                <label class="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked class="accent-green-600" />
                  Checked option
                </label>
                <label class="flex items-center gap-2 text-sm">
                  <input type="checkbox" class="accent-green-600" />
                  Unchecked option
                </label>
              </div>
              <div class="space-y-2">
                <label class="mb-1 block text-sm font-medium">
                  Radio Buttons
                </label>
                <label class="flex items-center gap-2 text-sm">
                  <input
                    type="radio"
                    name="demo-radio"
                    checked
                    class="accent-green-600"
                  />
                  Option A
                </label>
                <label class="flex items-center gap-2 text-sm">
                  <input
                    type="radio"
                    name="demo-radio"
                    class="accent-green-600"
                  />
                  Option B
                </label>
              </div>
            </div>
          </div>
        </Section>

        {/* Focus States */}
        <Section title="Focus States">
          <p class="text-sm text-muted">
            Tab through these elements to verify consistent keyboard focus
            indicators.
          </p>
          <div class="space-y-4">
            <div class="flex flex-wrap items-center gap-3">
              <button class="btn btn-primary" type="button">
                Button
              </button>
              <button class="btn" type="button">
                Secondary
              </button>
              <a href="#demo">Link</a>
              <a href="#demo" class="text-sm text-muted">
                Muted Link
              </a>
            </div>
            <div class="flex flex-wrap items-center gap-4">
              <input type="text" placeholder="Text input" class="input w-40" />
              <select class="select w-40">
                <option>Select</option>
              </select>
              <label class="flex items-center gap-2 text-sm">
                <input type="checkbox" class="accent-green-600" />
                Checkbox
              </label>
              <label class="flex items-center gap-2 text-sm">
                <input
                  type="radio"
                  name="focus-demo"
                  class="accent-green-600"
                />
                Radio
              </label>
            </div>
          </div>
        </Section>

        {/* Code */}
        <Section title="Inline Code &amp; Monospace">
          <p class="text-sm">
            Secret ID:{' '}
            <code class="rounded border border-border/50 bg-surface-raised px-1.5 py-0.5 font-mono text-xs select-all">
              abc123-def456-ghi789
            </code>
          </p>
          <div class="mt-2 overflow-x-auto rounded-lg bg-green-950 p-4 font-mono text-sm text-green-100">
            <pre>{`$ secrt send --ttl 1h "my secret"
https://secrt.ca/s/abc123#key=...`}</pre>
          </div>
        </Section>

        {/* Border radii */}
        <Section title="Border Radii">
          <div class="flex items-center gap-4">
            {(
              [
                'rounded-sm',
                'rounded',
                'rounded-md',
                'rounded-lg',
                'rounded-xl',
                'rounded-full',
              ] as const
            ).map((r) => (
              <div key={r} class="flex flex-col items-center gap-1">
                <div
                  class={`size-12 border-2 border-accent bg-accent/10 ${r}`}
                />
                <span class="text-xs text-muted">
                  {r.replace('rounded-', '').replace('rounded', 'default')}
                </span>
              </div>
            ))}
          </div>
        </Section>

        {/* Shadows */}
        <Section title="Shadows">
          <div class="flex items-center gap-6">
            <div class="flex flex-col items-center gap-1">
              <div class="size-16 rounded-lg bg-surface shadow-sm" />
              <span class="text-xs text-muted">shadow-sm</span>
            </div>
            <div class="flex flex-col items-center gap-1">
              <div class="size-16 rounded-lg bg-surface shadow-md" />
              <span class="text-xs text-muted">shadow-md</span>
            </div>
            <div class="flex flex-col items-center gap-1">
              <div class="size-16 rounded-lg bg-surface shadow-lg" />
              <span class="text-xs text-muted">shadow-lg</span>
            </div>
            <div class="flex flex-col items-center gap-1">
              <div class="size-16 rounded-lg bg-surface shadow-xl" />
              <span class="text-xs text-muted">shadow-xl</span>
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
