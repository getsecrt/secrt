import { useState, useEffect, useCallback } from 'preact/hooks';
import { ThemeToggle } from './ThemeToggle';
import { MenuIcon, XMarkIcon, UserCircleIcon, LogoutIcon, FingerprintIcon, GitHubIcon, DownloadIcon } from './Icons';
import { navigate, useRoute } from '../router';
import { useAuth } from '../lib/auth-context';

function NavLink({
  href,
  children,
  external,
  active,
  onClick,
  class: className,
}: {
  href: string;
  children: preact.ComponentChildren;
  external?: boolean;
  active?: boolean;
  onClick?: (e: MouseEvent) => void;
  class?: string;
}) {
  const base = 'text-sm transition-colors hover:text-text';
  const activeClass = active ? 'text-text font-medium' : 'text-muted';

  if (external) {
    return (
      <a
        href={href}
        class={`${base} ${activeClass} ${className ?? ''}`}
        target="_blank"
        rel="noopener noreferrer"
      >
        {children}
      </a>
    );
  }

  return (
    <a
      href={href}
      class={`${base} ${activeClass} ${className ?? ''}`}
      onClick={(e: MouseEvent) => {
        e.preventDefault();
        onClick?.(e);
        navigate(href);
      }}
    >
      {children}
    </a>
  );
}

export function Nav() {
  const [menuOpen, setMenuOpen] = useState(false);
  const route = useRoute();
  const auth = useAuth();

  // Close mobile menu on route change
  useEffect(() => {
    setMenuOpen(false);
  }, [route.page]);

  const toggleMenu = useCallback(() => setMenuOpen((o) => !o), []);

  const handleLogout = useCallback(async () => {
    await auth.logout();
    navigate('/');
  }, [auth]);

  const isActive = (page: string) => route.page === page;

  return (
    <nav class="sticky top-0 z-10 border-b border-border bg-surface/95 backdrop-blur">
      <div class="mx-auto flex max-w-lg items-center justify-center gap-4 px-4 py-2">
        {/* Desktop links (hidden below sm) */}
        <div class="hidden items-center gap-4 sm:flex">
          <NavLink href="/" active={isActive('send')}>
            Create
          </NavLink>
          <NavLink href="/how-it-works" active={isActive('how-it-works')}>
            How it Works
          </NavLink>
          <NavLink href="https://github.com/getsecrt/secrt" external>
            <span class="flex items-center gap-1">
              <GitHubIcon class="size-4" />
              GitHub
            </span>
          </NavLink>
          <NavLink href="https://github.com/getsecrt/secrt/releases" external>
            <span class="flex items-center gap-1">
              <DownloadIcon class="size-4" />
              Downloads
            </span>
          </NavLink>

          {/* Auth section */}
          {!auth.loading && (
            auth.authenticated ? (
              <div class="flex items-center gap-3">
                <span class="flex items-center gap-1 text-sm text-muted">
                  <UserCircleIcon class="size-4" />
                  {auth.handle}
                </span>
                <button
                  type="button"
                  class="flex items-center gap-1 text-sm text-muted transition-colors hover:text-text"
                  onClick={handleLogout}
                >
                  <LogoutIcon class="size-4" />
                  Log out
                </button>
              </div>
            ) : (
              <NavLink href="/login">
                <span class="flex items-center gap-1">
                  <FingerprintIcon class="size-4" />
                  Log in
                </span>
              </NavLink>
            )
          )}

          <ThemeToggle />
        </div>

        {/* Mobile: centered links + hamburger */}
        <div class="flex w-full items-center justify-between sm:hidden">
          <div class="flex items-center gap-3">
            <NavLink href="/" active={isActive('send')}>
              Create
            </NavLink>
            <NavLink href="/how-it-works" active={isActive('how-it-works')}>
              How it Works
            </NavLink>
          </div>
          <div class="flex items-center gap-2">
            <ThemeToggle />
            <button
              type="button"
              class="p-1 text-muted hover:text-text"
              onClick={toggleMenu}
              aria-label={menuOpen ? 'Close menu' : 'Open menu'}
              aria-expanded={menuOpen}
            >
              {menuOpen ? <XMarkIcon class="size-6" /> : <MenuIcon class="size-6" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile drawer */}
      {menuOpen && (
        <div class="border-t border-border px-4 pb-4 pt-2 sm:hidden">
          <div class="flex flex-col gap-3">
            <NavLink href="https://github.com/getsecrt/secrt" external>
              <span class="flex items-center gap-1">
                <GitHubIcon class="size-4" />
                GitHub
              </span>
            </NavLink>
            <NavLink href="https://github.com/getsecrt/secrt/releases" external>
              <span class="flex items-center gap-1">
                <DownloadIcon class="size-4" />
                Downloads
              </span>
            </NavLink>

            {!auth.loading && (
              auth.authenticated ? (
                <>
                  <span class="flex items-center gap-1 text-sm text-muted">
                    <UserCircleIcon class="size-4" />
                    {auth.handle}
                  </span>
                  <button
                    type="button"
                    class="flex items-center gap-1 text-sm text-muted transition-colors hover:text-text"
                    onClick={handleLogout}
                  >
                    <LogoutIcon class="size-4" />
                    Log out
                  </button>
                </>
              ) : (
                <NavLink href="/login">
                  <span class="flex items-center gap-1">
                    <FingerprintIcon class="size-4" />
                    Log in
                  </span>
                </NavLink>
              )
            )}
          </div>
        </div>
      )}
    </nav>
  );
}
