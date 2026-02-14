import type { ComponentChildren } from 'preact';
import { Logo } from './Logo';
import { Nav } from './Nav';
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

      <div class="flex flex-col items-center px-4 pt-6">
        <a class="flex justify-center" href="/" onClick={handleLogoClick}>
          <Logo />
        </a>
      </div>

      <main class="mx-auto flex w-full max-w-sm flex-col gap-6 px-4 py-6">
        {children}
      </main>

      <footer class="mt-auto py-4 text-center text-xs text-faint">
        &copy; {new Date().getFullYear()} secrt
      </footer>
    </div>
  );
}
