import { CardHeading } from '../../components/CardHeading';
import { navigate } from '../../router';

export function PrivacyPage() {
  const handleHome = (e: MouseEvent) => {
    e.preventDefault();
    navigate('/');
  };

  const Secrt = () => (
    <span class="text-black dark:text-white">
      s<span class="text-green-700 dark:text-green-400">e</span>crt
    </span>
  );

  return (
    <div class="space-y-10">
      <div class="card space-y-8 bg-white/20 dark:bg-black/20">
        <CardHeading
          title="Privacy Policy"
          subtitle="Last updated: February 17, 2026"
        />

        {/* TL;DR */}
        <section class="space-y-1">
          <h2 class="text-xl font-semibold">The short version:</h2>
          <p class="text-lg">
            We can't see your secrets. That's the whole point.
          </p>
        </section>

        {/* Zero-knowledge */}
        <section class="space-y-2">
          <h2 class="text-xl font-semibold">Zero-knowledge architecture</h2>
          <p class="leading-relaxed text-muted">
            Secrets are encrypted in your browser before they reach our server.
            The decryption key lives in the URL fragment (the part after{' '}
            <code class="rounded bg-black/5 px-1 py-0.5 text-xs dark:bg-white/10">
              #
            </code>
            ), which is{' '}
            <a
              href="https://www.rfc-editor.org/rfc/rfc3986#section-3.5"
              target="_blank"
              rel="noopener noreferrer"
              class="link"
            >
              never sent to the server
            </a>{' '}
            by your browser. We store only ciphertext — meaningless without the
            key. For a deeper explanation, see{' '}
            <a
              href="/how-it-works"
              onClick={(e: MouseEvent) => {
                e.preventDefault();
                navigate('/how-it-works');
              }}
              class="link"
            >
              How <Secrt /> Works
            </a>
            .
          </p>
        </section>

        {/* What we store */}
        <section class="space-y-2">
          <h2 class="text-xl font-semibold">What we store</h2>
          <ul class="list-inside list-disc space-y-1.5 text-muted">
            <li>
              <strong class="text-default">Encrypted secret payloads:</strong>
              deleted immediately after first read, or automatically on expiry
              (max 1 year)
            </li>
            <li>
              <strong class="text-default">Rate limiting data:</strong> IP
              addresses are HMAC-hashed with a per-process random key and held
              in memory only. Raw IPs are never written to the database. Stale
              entries are evicted every 2 minutes.
            </li>
            <li>
              <strong class="text-default">Account credentials:</strong> if you
              register (optional), we store your email and a passkey credential.
              No passwords — authentication is passkey-only.
            </li>
          </ul>
        </section>

        {/* What we don't store */}
        <section class="space-y-2">
          <h2 class="text-xl font-semibold">What we don't store</h2>
          <ul class="list-inside list-disc space-y-1.5 text-muted">
            <li>Your plaintext secrets — ever</li>
            <li>Decryption keys or URL fragments</li>
            <li>Analytics or tracking data</li>
            <li>Cookies beyond what's needed for authentication</li>
          </ul>
        </section>

        {/* IP privacy */}
        <section class="space-y-2">
          <h2 class="text-xl font-semibold">IP address privacy</h2>
          <p class="leading-relaxed text-muted">
            Our reverse proxy masks IP addresses in all access logs — the last
            octet of IPv4 addresses and the last 80 bits of IPv6 addresses are
            zeroed before writing to disk. User-Agent, Referer, and query
            strings are also stripped from logs. Log files are rotated and
            deleted after 7 days.
          </p>
        </section>

        {/* No tracking */}
        <section class="space-y-2">
          <h2 class="text-xl font-semibold">No tracking</h2>
          <p class="leading-relaxed text-muted">
            We don't use Google Analytics, tracking pixels, or any third-party
            analytics. No ads. No data brokers. No fingerprinting.
          </p>
        </section>

        {/* Infrastructure */}
        <section class="space-y-2">
          <h2 class="text-xl font-semibold">Infrastructure</h2>
          <p class="leading-relaxed text-muted">
            <Secrt /> is hosted on DigitalOcean in Canada. All connections use
            TLS. The server enforces HSTS with preload.
          </p>
        </section>

        {/* Open source */}
        <section class="space-y-2">
          <h2 class="text-xl font-semibold">Open source</h2>
          <p class="leading-relaxed text-muted">
            The entire codebase — client, server, CLI, and protocol
            specification — is{' '}
            <a
              href="https://github.com/getsecrt/secrt"
              target="_blank"
              rel="noopener noreferrer"
              class="link"
            >
              open source on GitHub
            </a>
            . You can audit every line, or run your own instance.
          </p>
        </section>

        {/* Contact */}
        <section class="space-y-2">
          <h2 class="text-xl font-semibold">Contact</h2>
          <p class="leading-relaxed text-muted">
            Questions or concerns:{' '}
            <a href="mailto:security@secrt.ca" class="link">
              security@secrt.ca
            </a>
          </p>
          <p class="leading-relaxed text-muted">
            Security vulnerabilities:{' '}
            <a
              href="https://github.com/getsecrt/secrt/blob/main/SECURITY.md"
              target="_blank"
              rel="noopener noreferrer"
              class="link"
            >
              security policy
            </a>
          </p>
        </section>
      </div>

      <div class="text-center">
        <a
          href="/"
          onClick={handleHome}
          class="hover:text-default text-muted transition-colors"
        >
          ← Back to <Secrt />
        </a>
      </div>
    </div>
  );
}
