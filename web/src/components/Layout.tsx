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

      <footer class="mt-auto flex flex-col items-center gap-1.5 py-4 text-xs text-faint">
        <a
          href="https://github.com/getsecrt/secrt"
          target="_blank"
          rel="noopener noreferrer"
          class="text-faint transition-colors hover:text-muted"
          aria-label="GitHub"
        >
          <GitHubIcon class="size-6" />
        </a>
        &copy; {new Date().getFullYear()} JD Lien
      </footer>
    </div>
  );
}
