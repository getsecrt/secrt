import { useCallback, useEffect } from 'preact/hooks';

function isDark(): boolean {
  return document.documentElement.classList.contains('dark');
}

function setDarkMode(dark: boolean): void {
  document.documentElement.classList.toggle('dark', dark);
  try {
    localStorage.setItem('theme', dark ? 'dark' : 'light');
  } catch {}
}

export function ThemeToggle() {
  const toggle = useCallback(() => setDarkMode(!isDark()), []);

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
      setDarkMode(!isDark());
    };

    document.addEventListener('keydown', onKeydown);
    return () => document.removeEventListener('keydown', onKeydown);
  }, []);

  return (
    <button
      type="button"
      class="relative inline-flex cursor-pointer gap-px rounded-full bg-surface-raised shadow-[inset_0_0_2px_1px_var(--color-neutral-200)] dark:bg-neutral-900 dark:shadow-[inset_0_0_2px_var(--color-neutral-800)]"
      role="switch"
      aria-label="Toggle dark mode"
      onClick={toggle}
    >
      <span
        class="absolute top-0 left-0 size-7 rounded-full bg-surface shadow-md transition-transform duration-200 dark:translate-x-[calc(100%+1px)]"
        aria-hidden="true"
      />
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
          stroke-linejoin="round"
        >
          <circle cx="12" cy="12" r="4" />
          <line x1="12" y1="2" x2="12" y2="4" />
          <line x1="12" y1="20" x2="12" y2="22" />
          <line x1="4.93" y1="4.93" x2="6.34" y2="6.34" />
          <line x1="17.66" y1="17.66" x2="19.07" y2="19.07" />
          <line x1="2" y1="12" x2="4" y2="12" />
          <line x1="20" y1="12" x2="22" y2="12" />
          <line x1="4.93" y1="19.07" x2="6.34" y2="17.66" />
          <line x1="17.66" y1="6.34" x2="19.07" y2="4.93" />
        </svg>
      </span>
      <span
        class="relative z-10 flex size-7 items-center justify-center rounded-full text-faint transition-colors hover:text-neutral-800 dark:bg-neutral-800 dark:text-muted dark:hover:bg-neutral-700 dark:hover:text-neutral-100"
        aria-hidden="true"
      >
        <svg
          class="size-3.5"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
          stroke-linecap="round"
          stroke-linejoin="round"
        >
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
        </svg>
      </span>
    </button>
  );
}
