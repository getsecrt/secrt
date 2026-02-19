import type { ComponentChildren } from 'preact';
import { Logo } from './Logo';
import { Nav } from './Nav';
import { GitHubIcon } from './Icons';
import { navigate } from '../router';

interface LayoutProps {
  children: ComponentChildren;
}

export function Layout({ children }: LayoutProps) {
  const handleLogoClick = (e: MouseEvent) => {
    e.preventDefault();
    navigate('/');
  };

  return (
    <div class="flex min-h-screen flex-col">
      <Nav />

      <div class="flex flex-col items-center px-4 pt-5">
        <a class="flex justify-center" href="/" onClick={handleLogoClick}>
          <Logo />
        </a>
        <p class="mt-1 text-center text-xs text-muted">
          Private, Zero-Knowledge, One-Time Secret Sharing
        </p>
      </div>

      <main class="mx-auto flex w-full max-w-2xl flex-col gap-6 px-4 py-6">
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
            <GitHubIcon class="size-5" />
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
