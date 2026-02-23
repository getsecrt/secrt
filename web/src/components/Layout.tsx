import type { ComponentChildren } from 'preact';
import { Logo } from './Logo';
import { Nav } from './Nav';
import { GitHubIcon } from './Icons';
import { navigate } from '../router';
import { useOnline } from '../hooks/useOnline';

interface LayoutProps {
  children: ComponentChildren;
  maxWidth?: string;
}

export function Layout({ children, maxWidth = 'max-w-2xl' }: LayoutProps) {
  const online = useOnline();

  const handleLogoClick = (e: MouseEvent) => {
    e.preventDefault();
    navigate('/');
  };

  return (
    <div class="flex min-h-screen flex-col">
      <a
        href="#main-content"
        class="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:rounded focus:bg-surface focus:px-4 focus:py-2 focus:text-text focus:shadow"
      >
        Skip to main content
      </a>
      <Nav />

      {!online && (
        <div role="alert" class="alert-error mx-2 mt-2 text-center sm:mx-4">
          You are offline. You cannot create or claim secrets until connectivity
          is restored.
        </div>
      )}

      <header class="flex flex-col items-center px-4 pt-1 sm:pt-4">
        <a class="flex justify-center" href="/" onClick={handleLogoClick}>
          <Logo class="hidden sm:block sm:w-40" />
        </a>
        <p class="mt-1 text-center text-xs text-muted">
          Zero-Knowledge One-Time Secret Sharing
        </p>
      </header>

      <main
        id="main-content"
        class={`mx-auto flex w-full ${maxWidth} flex-col gap-6 px-2 py-6 sm:px-4`}
      >
        {children}
      </main>

      <footer class="mt-auto flex flex-col items-center gap-2 pt-4 pb-[max(1rem,env(safe-area-inset-bottom))] text-xs text-faint">
        <div>
          <a
            href="https://github.com/getsecrt/secrt"
            target="_blank"
            rel="noopener noreferrer"
            class="text-faint transition-colors hover:text-muted"
            aria-label="GitHub"
          >
            <GitHubIcon class="size-5" aria-hidden="true" />
          </a>
        </div>

        <div class="flex flex-col items-center gap-2">
          <div>&copy; {new Date().getFullYear()} JD Lien</div>
          <a
            href="mailto:security@secrt.ca"
            class="link-subtle transition-colors"
          >
            security@secrt.ca
          </a>
        </div>

        <div class="flex items-center gap-3">
          <a
            href="/privacy"
            onClick={(e: MouseEvent) => {
              e.preventDefault();
              navigate('/privacy');
            }}
            class="link-subtle w-20 text-faint hover:text-muted"
          >
            Privacy Policy
          </a>
          <span class="text-faint/40">&bull;</span>
          <a
            href="/how-it-works"
            onClick={(e: MouseEvent) => {
              e.preventDefault();
              navigate('/how-it-works');
            }}
            class="link-subtle w-20 text-faint hover:text-muted"
          >
            How it Works
          </a>
        </div>
      </footer>
    </div>
  );
}
