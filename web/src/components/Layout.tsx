import type { ComponentChildren } from 'preact';
import { Logo } from './Logo';
import { ThemeToggle } from './ThemeToggle';
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
    <div class="flex min-h-screen flex-col items-center px-4 py-8">
      <header class="mb-6">
        <a href="/" onClick={handleLogoClick}>
          <Logo />
        </a>
      </header>

      <main class="flex w-full max-w-sm flex-col gap-6">{children}</main>

      <footer class="mt-8 flex flex-col items-center gap-4">
        <div class="flex justify-center gap-6 text-sm text-faint">
          <a href="https://github.com/getsecrt/secrt">GitHub</a>
          <a href="https://github.com/getsecrt/secrt/releases">Downloads</a>
        </div>
        <ThemeToggle />
      </footer>
    </div>
  );
}
