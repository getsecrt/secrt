import { navigate } from '../../router';
import { FaqSection } from '../../components/HowItWorks';

export function HowItWorksPage() {
  const handleHome = (e: MouseEvent) => {
    e.preventDefault();
    navigate('/');
  };

  return (
    <div class="space-y-8">
      <div class="space-y-2 text-center">
        <h1 class="heading">How secrt Works</h1>
        <p class="text-sm text-muted">
          A technical overview of our zero-knowledge architecture
        </p>
      </div>

      <section class="space-y-2">
        <h2 class="text-xl font-semibold text-black dark:text-white">
          Overview
        </h2>
        <p class="">
          <span class="text-black dark:text-white">
            s<span class="text-green-700 dark:text-green-400">e</span>crt
          </span>{' '}
          is a zero-knowledge, one-time secret sharing service. Your data is
          encrypted entirely in your browser before being sent to the server.
          The server stores only ciphertext — it never has access to your
          plaintext, decryption keys, or passphrases.
        </p>
      </section>

      <section class="space-y-2">
        <h2 class="text-xl font-semibold text-black dark:text-white">
          Encryption
        </h2>
        <p class="">
          When you create a secret, your browser generates a random 256-bit key
          and encrypts your content using <strong>AES-256-GCM</strong> — the
          same authenticated encryption standard used by governments and
          financial institutions. Key derivation uses{' '}
          <strong>HKDF-SHA-256</strong> to produce separate encryption and claim
          verification keys from a single root key.
        </p>
        <p class="">
          The encryption key is embedded in the share link's URL fragment (the
          part after{' '}
          <code class="rounded bg-surface-raised px-1 py-0.5 text-xs">#</code>).
          Fragments are never sent to the server by browsers, so the server
          never sees your key.
        </p>
      </section>

      <section class="space-y-2">
        <h2 class="text-xl font-semibold text-black dark:text-white">
          Passphrase Protection
        </h2>
        <p class="">
          For extra security, you can set a passphrase. This uses{' '}
          <strong>PBKDF2-SHA-256</strong> with 600,000 iterations to derive a
          secondary key. The final encryption key is then derived from both the
          URL key and the passphrase key combined. Even if someone intercepts
          the share link, they cannot decrypt the secret without the passphrase.
        </p>
      </section>

      <section class="space-y-2">
        <h2 class="text-xl font-semibold text-black dark:text-white">
          One-Time Retrieval
        </h2>
        <p class="">
          Each secret can only be retrieved once. When the recipient opens the
          link, the server returns the ciphertext and immediately, atomically
          deletes it. There is no second chance — if you refresh the page, the
          secret is already gone. This ensures that even if the link is later
          discovered, the secret is no longer accessible.
        </p>
      </section>

      <section class="space-y-2">
        <h2 class="text-xl font-semibold text-black dark:text-white">
          What the Server Sees
        </h2>
        <ul class="list-inside list-disc space-y-1">
          <li>Encrypted ciphertext (opaque bytes it cannot decrypt)</li>
          <li>A claim verifier hash (to authenticate retrieval)</li>
          <li>Expiry time and creation timestamp</li>
        </ul>
        <p class="mt-2">
          The server never sees: your plaintext, encryption keys, passphrases,
          filenames, or any metadata about your secret's content.
        </p>
      </section>

      <section class="space-y-2">
        <h2 class="text-xl font-semibold text-black dark:text-white">
          Open Source
        </h2>
        <p class="">
          The entire codebase — client, server, and cryptographic specification
          — is open source. You can audit the code, run your own instance, or
          verify that our claims are accurate. The protocol specification
          includes test vectors that any implementation must pass.
        </p>
        <p class="">
          <a class="link" href="https://github.com/getsecrt/secrt">
            View source on GitHub →
          </a>
        </p>
      </section>

      <FaqSection />

      <div>
        <h2 class="heading mt-10 text-center">Technical Whitepaper</h2>
        <p class="">
          For an in depth analysis of the architecture of secrt, please refer to
          the{' '}
          <a
            class="link"
            href="https://github.com/getsecrt/secrt/blob/main/docs/whitepaper.md"
          >
            secrt technical whitepaper
          </a>{' '}
          on GitHub.
        </p>
      </div>

      <div class="text-center">
        <a href="/" class="link" onClick={handleHome}>
          Home
        </a>
      </div>
    </div>
  );
}
