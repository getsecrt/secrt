import { useState, useEffect } from 'preact/hooks';
import { CardHeading } from '../../components/CardHeading';
import {
  DocumentIcon,
  EyeSlashIcon,
  GearIcon,
  GitHubIcon,
  LockIcon,
} from '../../components/Icons';
import { isTauri, getSecurityEmail } from '../../lib/config';
import { navigate } from '../../router';

/** Build-time version injected by Vite from the workspace Cargo.toml. */
const BUILD_VERSION: string = import.meta.env.VITE_APP_VERSION ?? 'unknown';

export function AboutPage() {
  const [version, setVersion] = useState(BUILD_VERSION);
  const securityEmail = getSecurityEmail();

  // In Tauri, override with the runtime version (authoritative for the app binary).
  useEffect(() => {
    if (!isTauri()) return;
    import('@tauri-apps/api/app').then(({ getVersion }) =>
      getVersion().then(setVersion),
    );
  }, []);

  return (
    <div class="card text-center">
      <CardHeading title="About Secrt" />

      <p class="mb-4 text-sm font-bold">
        Version <span class="font-mono">{version}</span>
      </p>

      <p class="mb-6 text-sm leading-relaxed text-muted">
        For any questions, concerns, or to report urgent security issues, email
        <br />
        <a href={`mailto:${securityEmail}`} class="link">
          {securityEmail}
        </a>
      </p>

      <div class="flex flex-wrap items-center justify-center gap-4">
        <a
          href="/how-it-works"
          onClick={(e: MouseEvent) => {
            e.preventDefault();
            navigate('/how-it-works');
          }}
          class="inline-flex flex-col items-center rounded border border-neutral-500/15 bg-neutral-500/10 p-1.5 text-sm text-muted transition-colors hover:border-neutral-500/25 hover:bg-neutral-300/15 hover:text-text"
        >
          <GearIcon class="size-4" />
          How it Works
        </a>

        <a
          href="https://github.com/getsecrt/secrt/blob/main/SECURITY.md"
          target="_blank"
          rel="noopener noreferrer"
          class="link-subtle inline-flex flex-col items-center text-sm text-muted transition-colors hover:text-text"
        >
          <LockIcon class="size-4" />
          Security Policy
        </a>

        <a
          href="/privacy"
          onClick={(e: MouseEvent) => {
            e.preventDefault();
            navigate('/privacy');
          }}
          class="link-subtle inline-flex flex-col items-center text-sm text-muted transition-colors hover:text-text"
        >
          <EyeSlashIcon class="size-4" />
          Privacy Policy
        </a>

        <a
          href="https://github.com/getsecrt/secrt/blob/main/docs/whitepaper.md"
          target="_blank"
          rel="noopener noreferrer"
          class="link-subtle inline-flex flex-col items-center text-sm text-muted transition-colors hover:text-text"
        >
          <DocumentIcon class="size-4" />
          Whitepaper
        </a>

        <a
          href="https://github.com/getsecrt/secrt"
          target="_blank"
          rel="noopener noreferrer"
          class="link-subtle inline-flex flex-col items-center text-sm text-muted transition-colors hover:text-text"
        >
          <GitHubIcon class="size-4" />
          Source Code
        </a>
      </div>

      <p class="mt-6 text-xs text-faint">
        &copy; {new Date().getFullYear()} JD Lien
      </p>
    </div>
  );
}
