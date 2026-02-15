import { useState, useEffect, useCallback, useRef } from 'preact/hooks';
import { ThemeToggle } from './ThemeToggle';
import {
  MenuIcon,
  XMarkIcon,
  UserIcon,
  LogoutIcon,
  PasskeyIcon,
  GitHubIcon,
  DownloadIcon,
  CircleQuestionIcon,
  SquarePlusIcon,
  TableIcon,
  GearIcon,
  ChevronDownIcon,
} from './Icons';
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
  const base = 'text-sm transition-colors hover:text-text rounded-md px-2 py-1';
  const activeClass = active ? 'text-text bg-text/10' : 'text-muted';

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

function UserMenu({
  displayName,
  onLogout,
}: {
  displayName: string;
  onLogout: () => void;
}) {
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);

  // Position and show the popover once it mounts
  useEffect(() => {
    const menu = menuRef.current;
    const trigger = triggerRef.current;
    if (!open || !menu || !trigger) return;

    menu.setAttribute('popover', 'auto');

    const rect = trigger.getBoundingClientRect();
    menu.style.position = 'fixed';
    menu.style.top = `${rect.bottom}px`;
    menu.style.right = `${window.innerWidth - rect.right}px`;
    menu.style.left = 'auto';
    menu.style.margin = '0';
    menu.style.minWidth = `${rect.width}px`;

    menu.showPopover();

    const onToggle = () => {
      if (!menu.matches(':popover-open')) setOpen(false);
    };
    menu.addEventListener('toggle', onToggle);
    return () => menu.removeEventListener('toggle', onToggle);
  }, [open]);

  const itemClass =
    'flex w-full items-center gap-2 whitespace-nowrap rounded-md px-3 py-1.5 text-sm text-muted transition-colors hover:bg-text/10 hover:text-text';

  const triggerClass = open
    ? 'flex items-center gap-1 whitespace-nowrap rounded-t-lg px-2 py-1 text-sm text-text bg-neutral-200/70 backdrop-blur dark:bg-neutral-700/70 border border-border/50 border-b-transparent'
    : 'flex items-center gap-1 whitespace-nowrap rounded-md px-2 py-1 text-sm text-muted transition-colors hover:text-text border border-transparent';

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        class={triggerClass}
        onClick={() => setOpen(true)}
      >
        <UserIcon class="size-4" />
        {displayName}
        <ChevronDownIcon class="size-3" />
      </button>
      {open && (
        <div
          ref={menuRef}
          id="user-menu"
          class="rounded-b-lg inset-shadow-border-3 bg-neutral-200/70 p-1 shadow-lg backdrop-blur dark:bg-neutral-700/70"
        >
          <a
            href="/dashboard"
            class={itemClass}
            onClick={(e: MouseEvent) => {
              e.preventDefault();
              setOpen(false);
              navigate('/dashboard');
            }}
          >
            <TableIcon class="size-4" />
            Dashboard
          </a>
          <a
            href="/settings"
            class={itemClass}
            onClick={(e: MouseEvent) => {
              e.preventDefault();
              setOpen(false);
              navigate('/settings');
            }}
          >
            <GearIcon class="size-4" />
            Settings
          </a>
          <button
            type="button"
            class={itemClass}
            onClick={() => {
              setOpen(false);
              onLogout();
            }}
          >
            <LogoutIcon class="size-4" />
            Log out
          </button>
        </div>
      )}
    </>
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
    <nav class="sticky top-0 z-10">
      <div class="border-b border-border bg-neutral-200/50 shadow-sm backdrop-blur dark:bg-neutral-700/50">
        <div class="mx-auto flex max-w-lg items-center justify-center gap-4 px-4 py-1.5">
        {/* Desktop links (hidden below sm) */}
        <div class="hidden items-center gap-6 sm:flex">
          <NavLink href="/" active={isActive('send')}>
            <span class="flex items-center gap-1 whitespace-nowrap">
              <SquarePlusIcon class="size-4" />
              Create
            </span>
          </NavLink>

          <NavLink href="/how-it-works" active={isActive('how-it-works')}>
            <span class="flex items-center gap-1 whitespace-nowrap">
              <CircleQuestionIcon class="size-4" />
              How it Works
            </span>
          </NavLink>

          <NavLink href="https://github.com/getsecrt/secrt/releases" external>
            <span class="flex items-center gap-1 whitespace-nowrap">
              <DownloadIcon class="size-4" />
              Downloads
            </span>
          </NavLink>

          <NavLink href="https://github.com/getsecrt/secrt" external>
            <span class="flex items-center gap-1 whitespace-nowrap">
              <GitHubIcon class="size-4" />
              GitHub
            </span>
          </NavLink>

          {/* Auth section */}
          {!auth.loading &&
            (auth.authenticated ? (
              <UserMenu displayName={auth.displayName!} onLogout={handleLogout} />
            ) : (
              <NavLink href="/login" active={isActive('login')}>
                <span class="flex items-center gap-1 whitespace-nowrap">
                  <PasskeyIcon class="size-4" />
                  Log In
                </span>
              </NavLink>
            ))}

          <ThemeToggle />
        </div>

        {/* Mobile: hamburger + theme toggle */}
        <div class="flex w-full items-center justify-between sm:hidden">
          <button
            type="button"
            class="p-1 text-muted hover:text-text"
            onClick={toggleMenu}
            aria-label={menuOpen ? 'Close menu' : 'Open menu'}
            aria-expanded={menuOpen}
          >
            {menuOpen ? (
              <XMarkIcon class="size-6" />
            ) : (
              <MenuIcon class="size-6" />
            )}
          </button>
          <ThemeToggle />
        </div>
        </div>
      </div>

      {/* Mobile drawer (overlay) */}
      {menuOpen && (
        <>
        <div class="fixed inset-0 sm:hidden" onClick={() => setMenuOpen(false)} />
        <div class="absolute left-0 right-0 border-t border-border bg-neutral-200/70 px-4 pt-2 pb-4 shadow-lg backdrop-blur-xs sm:hidden dark:bg-neutral-700/80">
          <div class="flex flex-col gap-3">
            {!auth.loading && auth.authenticated && (
              <div class="mb-1 border-b border-border px-2 py-1 pb-2 text-sm text-black/55 dark:text-white/55">
                <span class="flex items-center gap-1.5">
                  <UserIcon class="size-4" />
                  {auth.displayName}
                </span>
              </div>
            )}

            <NavLink href="/" active={isActive('send')}>
              <span class="flex items-center gap-1 whitespace-nowrap">
                <SquarePlusIcon class="size-4" />
                Create
              </span>
            </NavLink>
            <NavLink href="/how-it-works" active={isActive('how-it-works')}>
              <span class="flex items-center gap-1 whitespace-nowrap">
                <CircleQuestionIcon class="size-4" />
                How it Works
              </span>
            </NavLink>

            <NavLink href="https://github.com/getsecrt/secrt/releases" external>
              <span class="flex items-center gap-1 whitespace-nowrap">
                <DownloadIcon class="size-4" />
                Downloads
              </span>
            </NavLink>

            <NavLink href="https://github.com/getsecrt/secrt" external>
              <span class="flex items-center gap-1 whitespace-nowrap">
                <GitHubIcon class="size-4" />
                GitHub
              </span>
            </NavLink>

            {!auth.loading &&
              (auth.authenticated ? (
                <>
                  <NavLink href="/dashboard" active={isActive('dashboard')}>
                    <span class="flex items-center gap-1 whitespace-nowrap">
                      <TableIcon class="size-4" />
                      Dashboard
                    </span>
                  </NavLink>
                  <NavLink href="/settings" active={isActive('settings')}>
                    <span class="flex items-center gap-1 whitespace-nowrap">
                      <GearIcon class="size-4" />
                      Settings
                    </span>
                  </NavLink>
                  <button
                    type="button"
                    class="flex items-center gap-1 whitespace-nowrap rounded-md px-2 py-1 text-sm text-muted transition-colors hover:text-text"
                    onClick={handleLogout}
                  >
                    <LogoutIcon class="size-4" />
                    Log out
                  </button>
                </>
              ) : (
                <NavLink href="/login" active={isActive('login')}>
                  <span class="flex items-center gap-1 whitespace-nowrap">
                    <PasskeyIcon class="size-4" />
                    Log In
                  </span>
                </NavLink>
              ))}
          </div>
        </div>
        </>
      )}
    </nav>
  );
}
