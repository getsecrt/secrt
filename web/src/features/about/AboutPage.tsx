import { useState, useEffect } from 'preact/hooks';
import { CardHeading } from '../../components/CardHeading';
import { GitHubIcon, LockIcon } from '../../components/Icons';
import { isTauri } from '../../lib/config';

/** Build-time version injected by Vite from the workspace Cargo.toml. */
const BUILD_VERSION: string = import.meta.env.VITE_APP_VERSION ?? 'unknown';

export function AboutPage() {
  const [version, setVersion] = useState(BUILD_VERSION);

  // In Tauri, override with the runtime version (authoritative for the app binary).
  useEffect(() => {
    if (!isTauri()) return;
    import('@tauri-apps/api/app').then(({ getVersion }) =>
      getVersion().then(setVersion),
    );
  }, []);

  return (
    <div class="card text-center">
      <CardHeading
        title="About Secrt"
        subtitle="Zero-knowledge one-time secret sharing"
      />

      <p class="mb-4 text-sm text-muted">
        Version <span class="font-mono">{version}</span>
      </p>

      <p class="mb-6 text-sm leading-relaxed text-muted">
        All encryption happens on your device. The server never sees your
        secrets, passphrases, or decryption keys.
      </p>

      <div class="flex flex-col items-center gap-3">
        <a
          href="https://github.com/getsecrt/secrt"
          target="_blank"
          rel="noopener noreferrer"
          class="inline-flex items-center gap-1.5 text-sm text-muted transition-colors hover:text-text"
        >
          <GitHubIcon class="size-4" />
          Source Code
        </a>
        <a
          href="https://github.com/getsecrt/secrt/blob/main/SECURITY.md"
          target="_blank"
          rel="noopener noreferrer"
          class="inline-flex items-center gap-1.5 text-sm text-muted transition-colors hover:text-text"
        >
          <LockIcon class="size-4" />
          Security Policy
        </a>
      </div>

      <p class="mt-6 text-xs text-faint">
        &copy; {new Date().getFullYear()} JD Lien
      </p>
    </div>
  );
}
