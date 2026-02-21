import {
  useState,
  useEffect,
  useLayoutEffect,
  useCallback,
  useRef,
} from 'preact/hooks';
import { Logo } from './Logo';
import { ThemeToggle } from './ThemeToggle';
import {
  MenuIcon,
  XMarkIcon,
  UserIcon,
  LogoutIcon,
  PasskeyIcon,
  DownloadIcon,
  CircleQuestionIcon,
  EyeSlashIcon,
  LockIcon,
  GitHubIcon,
  SquarePlusIcon,
  TableIcon,
  GearIcon,
  ChevronDownIcon,
  AppleIcon,
  WindowsIcon,
  LinuxIcon,
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

  // Position and show the popover before first paint
  useLayoutEffect(() => {
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

  const userMenuClass =
    'min-w-[127px] flex justify-around items-center gap-1 whitespace-nowrap px-2 py-1 text-sm border';
  const triggerClass = open
    ? userMenuClass +
      ' rounded-t-lg text-text bg-neutral-200/70 backdrop-blur dark:bg-neutral-700/70 border-border/50 border-b-transparent'
    : userMenuClass +
      ' rounded-md text-muted transition-colors hover:text-text border-transparent';

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        class={triggerClass}
        onClick={() => setOpen(true)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? 'user-menu' : undefined}
      >
        <div class="flex items-center gap-1">
          <UserIcon class="size-4" aria-hidden="true" />
          {displayName}
        </div>
        <ChevronDownIcon class="size-3" aria-hidden="true" />
      </button>
      {open && (
        <div
          ref={menuRef}
          id="user-menu"
          role="menu"
          class="rounded-b-lg bg-neutral-200/70 p-1 shadow-lg inset-shadow-border-3 backdrop-blur dark:bg-neutral-700/70"
        >
          <a
            href="/dashboard"
            role="menuitem"
            class={itemClass}
            onClick={(e: MouseEvent) => {
              e.preventDefault();
              setOpen(false);
              navigate('/dashboard');
            }}
          >
            <TableIcon class="size-4" aria-hidden="true" />
            Dashboard
          </a>
          <a
            href="/settings"
            role="menuitem"
            class={itemClass}
            onClick={(e: MouseEvent) => {
              e.preventDefault();
              setOpen(false);
              navigate('/settings');
            }}
          >
            <GearIcon class="size-4" aria-hidden="true" />
            Settings
          </a>
          <button
            type="button"
            role="menuitem"
            class={itemClass}
            onClick={() => {
              setOpen(false);
              onLogout();
            }}
          >
            <LogoutIcon class="size-4" aria-hidden="true" />
            Log out
          </button>
        </div>
      )}
    </>
  );
}

const DOWNLOAD_BASE =
  'https://github.com/getsecrt/secrt/releases/latest/download';

const downloadLinks = [
  {
    label: 'macOS',
    href: `${DOWNLOAD_BASE}/secrt-macos.pkg`,
    icon: AppleIcon,
  },
  {
    label: 'Windows x64',
    href: `${DOWNLOAD_BASE}/secrt-windows-amd64.zip`,
    icon: WindowsIcon,
  },
  {
    label: 'Windows ARM',
    href: `${DOWNLOAD_BASE}/secrt-windows-arm64.zip`,
    icon: WindowsIcon,
  },
  {
    label: 'Linux x64',
    href: `${DOWNLOAD_BASE}/secrt-linux-amd64.tar.gz`,
    icon: LinuxIcon,
  },
  {
    label: 'Linux ARM',
    href: `${DOWNLOAD_BASE}/secrt-linux-arm64.tar.gz`,
    icon: LinuxIcon,
  },
];

function DownloadsMenu() {
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);

  useLayoutEffect(() => {
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

  const downloadsMenuClass =
    'flex justify-around items-center gap-1 whitespace-nowrap px-2 py-1 text-sm border';
  const triggerClass = open
    ? downloadsMenuClass +
      ' rounded-t-lg text-text bg-neutral-200/70 backdrop-blur dark:bg-neutral-700/70 border-border/50 border-b-transparent'
    : downloadsMenuClass +
      ' rounded-md text-muted transition-colors hover:text-text border-transparent';

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        class={triggerClass}
        onClick={() => setOpen(true)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? 'downloads-menu' : undefined}
      >
        <div class="flex items-center gap-1">
          <DownloadIcon class="size-4" aria-hidden="true" />
          CLI Downloads
        </div>
        <ChevronDownIcon class="size-3" aria-hidden="true" />
      </button>
      {open && (
        <div
          ref={menuRef}
          id="downloads-menu"
          role="menu"
          class="rounded-b-lg bg-neutral-200/70 p-1 shadow-lg inset-shadow-border-3 backdrop-blur dark:bg-neutral-700/70"
        >
          {downloadLinks.map(({ label, href, icon: Icon }) => (
            <a
              key={label}
              href={href}
              role="menuitem"
              class={itemClass}
              target="_blank"
              rel="noopener noreferrer"
            >
              <Icon class="size-4" aria-hidden="true" />
              {label}
            </a>
          ))}
        </div>
      )}
    </>
  );
}

function MoreInfoMenu({ active }: { active?: boolean }) {
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);

  useLayoutEffect(() => {
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

  const moreInfoMenuClass =
    'flex justify-around items-center gap-1 whitespace-nowrap px-2 py-1 text-sm border';
  const triggerClass = open
    ? moreInfoMenuClass +
      ' rounded-t-lg text-text bg-neutral-200/70 backdrop-blur dark:bg-neutral-700/70 border-border/50 border-b-transparent'
    : moreInfoMenuClass +
      ` rounded-md transition-colors hover:text-text border-transparent ${active ? 'text-text bg-text/10' : 'text-muted'}`;

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        class={triggerClass}
        onClick={() => setOpen(true)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? 'more-info-menu' : undefined}
      >
        <div class="flex items-center gap-1">
          <CircleQuestionIcon class="size-4" aria-hidden="true" />
          More Information
        </div>
        <ChevronDownIcon class="size-3" aria-hidden="true" />
      </button>
      {open && (
        <div
          ref={menuRef}
          id="more-info-menu"
          role="menu"
          class="rounded-b-lg bg-neutral-200/70 p-1 shadow-lg inset-shadow-border-3 backdrop-blur dark:bg-neutral-700/70"
        >
          <a
            href="/how-it-works"
            role="menuitem"
            class={itemClass}
            onClick={(e: MouseEvent) => {
              e.preventDefault();
              setOpen(false);
              navigate('/how-it-works');
            }}
          >
            <GearIcon class="size-4" aria-hidden="true" />
            How it Works
          </a>
          <a
            href="/privacy"
            role="menuitem"
            class={itemClass}
            onClick={(e: MouseEvent) => {
              e.preventDefault();
              setOpen(false);
              navigate('/privacy');
            }}
          >
            <EyeSlashIcon class="size-4" aria-hidden="true" />
            Privacy Policy
          </a>
          <a
            href="https://github.com/getsecrt/secrt/blob/main/SECURITY.md"
            role="menuitem"
            class={itemClass}
            target="_blank"
            rel="noopener noreferrer"
          >
            <LockIcon class="size-4" aria-hidden="true" />
            Security Policy
          </a>
          <a
            href="https://github.com/getsecrt/secrt"
            role="menuitem"
            class={itemClass}
            target="_blank"
            rel="noopener noreferrer"
          >
            <GitHubIcon class="size-4" aria-hidden="true" />
            GitHub Repo
          </a>
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

  const navItemClass = 'flex items-center gap-1 whitespace-nowrap';

  return (
    <nav class="sticky top-0 z-10">
      <div class="border-b border-border bg-neutral-200/50 pt-[env(safe-area-inset-top)] shadow-sm backdrop-blur dark:bg-neutral-700/50">
        <div class="mx-auto flex max-w-lg items-center justify-center gap-4 px-4 py-1.5">
          {/* Desktop links (hidden below sm) */}
          <div class="hidden items-center gap-6 sm:flex">
            <NavLink href="/" active={isActive('send')}>
              <span class={navItemClass}>
                <SquarePlusIcon class="size-4" aria-hidden="true" />
                Create
              </span>
            </NavLink>

            <MoreInfoMenu
              active={isActive('how-it-works') || isActive('privacy')}
            />

            <DownloadsMenu />

            {/* Auth section */}
            {!auth.loading &&
              (auth.authenticated ? (
                <UserMenu
                  displayName={auth.displayName!}
                  onLogout={handleLogout}
                />
              ) : (
                <NavLink href="/login" active={isActive('login')}>
                  <span class={navItemClass}>
                    <PasskeyIcon class="size-4" aria-hidden="true" />
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
              class="w-15 p-1 text-muted hover:text-text"
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

            <Logo class="w-22" />

            <div class="w-15">
              <ThemeToggle />
            </div>
          </div>
        </div>
      </div>

      {/* Mobile drawer (overlay) */}
      {menuOpen && (
        <>
          <div
            class="fixed inset-0 sm:hidden"
            aria-hidden="true"
            onClick={() => setMenuOpen(false)}
          />
          <div class="absolute right-0 left-0 border-t border-border bg-neutral-200/70 px-4 pt-2 pb-4 shadow-lg backdrop-blur-xs sm:hidden dark:bg-neutral-700/80">
            <div class="flex flex-col gap-3">
              {!auth.loading && auth.authenticated && (
                <div class="mb-1 flex items-center justify-between border-b border-border px-2 py-1 pb-2 text-sm text-black/55 dark:text-white/55">
                  <span class="flex items-center gap-1.5">
                    <UserIcon class="size-4" aria-hidden="true" />
                    {auth.displayName}
                  </span>
                  <button
                    type="button"
                    class="flex items-center gap-1 rounded-md px-2 py-1 text-muted transition-colors hover:text-text"
                    onClick={handleLogout}
                  >
                    <LogoutIcon class="size-4" aria-hidden="true" />
                    Log out
                  </button>
                </div>
              )}

              {!auth.loading && !auth.authenticated && (
                <NavLink href="/login" active={isActive('login')}>
                  <span class={navItemClass}>
                    <PasskeyIcon class="size-4" aria-hidden="true" />
                    Log In / Register
                  </span>
                </NavLink>
              )}

              <NavLink href="/" active={isActive('send')}>
                <span class={navItemClass}>
                  <SquarePlusIcon class="size-4" aria-hidden="true" />
                  Create
                </span>
              </NavLink>

              {!auth.loading && auth.authenticated && (
                <>
                  <NavLink href="/dashboard" active={isActive('dashboard')}>
                    <span class={navItemClass}>
                      <TableIcon class="size-4" aria-hidden="true" />
                      Dashboard
                    </span>
                  </NavLink>
                  <NavLink href="/settings" active={isActive('settings')}>
                    <span class={navItemClass}>
                      <GearIcon class="size-4" aria-hidden="true" />
                      Settings
                    </span>
                  </NavLink>
                </>
              )}

              <div class="flex flex-col gap-1">
                <span class="flex items-center gap-1 px-2 text-sm text-muted">
                  <CircleQuestionIcon class="size-4" aria-hidden="true" />
                  More Information
                </span>
                <NavLink
                  href="/how-it-works"
                  active={isActive('how-it-works')}
                  class="pl-6"
                >
                  <span class={navItemClass}>
                    <GearIcon class="size-4" aria-hidden="true" />
                    How it Works
                  </span>
                </NavLink>
                <NavLink
                  href="/privacy"
                  active={isActive('privacy')}
                  class="pl-6"
                >
                  <span class={navItemClass}>
                    <EyeSlashIcon class="size-4" aria-hidden="true" />
                    Privacy Policy
                  </span>
                </NavLink>
                <NavLink
                  href="https://github.com/getsecrt/secrt/blob/main/SECURITY.md"
                  external
                  class="pl-6"
                >
                  <span class={navItemClass}>
                    <LockIcon class="size-4" aria-hidden="true" />
                    Security Policy
                  </span>
                </NavLink>
                <NavLink
                  href="https://github.com/getsecrt/secrt"
                  external
                  class="pl-6"
                >
                  <span class={navItemClass}>
                    <GitHubIcon class="size-4" aria-hidden="true" />
                    GitHub Repository
                  </span>
                </NavLink>
              </div>

              <div class="flex flex-col gap-1">
                <span class="flex items-center gap-1 px-2 text-sm text-muted">
                  <DownloadIcon class="size-4" aria-hidden="true" />
                  CLI Downloads
                </span>
                {downloadLinks.map(({ label, href, icon: Icon }) => (
                  <NavLink key={label} href={href} external class="pl-6">
                    <span class={navItemClass}>
                      <Icon class="size-4" />
                      {label}
                    </span>
                  </NavLink>
                ))}
              </div>
            </div>
          </div>
        </>
      )}
    </nav>
  );
}
