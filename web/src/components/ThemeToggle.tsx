import { useCallback, useEffect, useState } from 'preact/hooks';
import { isDark, setDarkMode } from '../lib/theme';

export function ThemeToggle({ class: className }: { class?: string }) {
  const [dark, setDark] = useState(isDark);
  const toggle = useCallback(() => {
    const next = !isDark();
    setDarkMode(next);
    setDark(next);
  }, []);

  useEffect(() => {
    const onKeydown = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key.toLowerCase() !== 'd') return;
      const t = e.target;
      if (
        t instanceof HTMLElement &&
        (t.isContentEditable ||
          t.tagName === 'INPUT' ||
          t.tagName === 'TEXTAREA' ||
          t.tagName === 'SELECT')
      )
        return;

      e.preventDefault();
      const next = !isDark();
      setDarkMode(next);
      setDark(next);
    };

    document.addEventListener('keydown', onKeydown);
    return () => document.removeEventListener('keydown', onKeydown);
  }, []);

  return (
    <button
      type="button"
      class={`theme-toggle-track relative inline-flex cursor-pointer gap-px rounded-full bg-surface-raised dark:bg-neutral-900${className ? ` ${className}` : ''}`}
      role="switch"
      aria-label="Toggle dark mode"
      aria-checked={dark}
      onClick={toggle}
    >
      <span
        class="relative z-10 flex size-7 items-center justify-center rounded-full text-muted transition-colors hover:text-neutral-800 dark:text-faint dark:hover:text-neutral-200"
        aria-hidden="true"
      >
        <svg
          class="size-3.5"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
          stroke-linecap="round"
        >
          <circle cx="12" cy="12" r="4" />
          <line x1="12" y1="2" x2="12" y2="4" />
          <line x1="12" y1="20" x2="12" y2="22" />
          <line x1="5" y1="5" x2="6.3" y2="6.3" />
          <line x1="17.7" y1="17.7" x2="19" y2="19" />
          <line x1="2" y1="12" x2="4" y2="12" />
          <line x1="20" y1="12" x2="22" y2="12" />
          <line x1="5" y1="19" x2="6.3" y2="17.7" />
          <line x1="17.7" y1="6.3" x2="19" y2="5" />
        </svg>
      </span>
      <span
        class="relative z-10 flex size-7 items-center justify-center rounded-full text-faint transition-colors hover:text-neutral-800 dark:text-muted dark:hover:bg-neutral-750 dark:hover:text-neutral-100"
        aria-hidden="true"
      >
        <svg
          class="size-3.5"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
        >
          <path d="M21 12.79A9 9 0 1 1 11.2 3 7 7 0 0 0 21 13z" />
        </svg>
      </span>

      <span
        class="theme-toggle-knob absolute top-0 left-0 size-7 rounded-full bg-surface transition-transform duration-200 hover:bg-white dark:translate-x-[calc(100%+1px)] dark:bg-neutral-800 dark:hover:bg-neutral-600"
        aria-hidden="true"
      />
    </button>
  );
}
