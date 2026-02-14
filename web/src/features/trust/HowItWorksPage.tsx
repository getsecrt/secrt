import { navigate } from '../../router';

export function HowItWorksPage() {
  const handleHome = (e: MouseEvent) => {
    e.preventDefault();
    navigate('/');
  };

  return (
    <div class="card space-y-8">
      <div class="space-y-2 text-center">
        <h1 class="text-xl font-bold">How secrt Works</h1>
        <p class="text-sm text-muted">
          A technical overview of our zero-knowledge architecture
        </p>
      </div>

      <section class="space-y-2">
        <h2 class="text-base font-semibold">Overview</h2>
        <p class="text-sm text-muted">
          secrt is a zero-knowledge, one-time secret sharing service. Your data
          is encrypted entirely in your browser before being sent to the server.
          The server stores only ciphertext — it never has access to your
          plaintext, decryption keys, or passphrases.
        </p>
      </section>

      <section class="space-y-2">
        <h2 class="text-base font-semibold">Encryption</h2>
        <p class="text-sm text-muted">
          When you create a secret, your browser generates a random 256-bit key
          and encrypts your content using <strong>AES-256-GCM</strong> — the
          same authenticated encryption standard used by governments and
          financial institutions. Key derivation uses{' '}
          <strong>HKDF-SHA-256</strong> to produce separate encryption and claim
          verification keys from a single root key.
        </p>
        <p class="text-sm text-muted">
          The encryption key is embedded in the share link's URL fragment (the
          part after <code class="rounded bg-surface-raised px-1 py-0.5 text-xs">#</code>).
          Fragments are never sent to the server by browsers, so the server
          never sees your key.
        </p>
      </section>

      <section class="space-y-2">
        <h2 class="text-base font-semibold">Passphrase Protection</h2>
        <p class="text-sm text-muted">
          For extra security, you can set a passphrase. This uses{' '}
          <strong>PBKDF2-SHA-256</strong> with 600,000 iterations to derive a
          secondary key. The final encryption key is then derived from both the
          URL key and the passphrase key combined. Even if someone intercepts the
          share link, they cannot decrypt the secret without the passphrase.
        </p>
      </section>

      <section class="space-y-2">
        <h2 class="text-base font-semibold">One-Time Retrieval</h2>
        <p class="text-sm text-muted">
          Each secret can only be retrieved once. When the recipient opens the
          link, the server returns the ciphertext and immediately, atomically
          deletes it. There is no second chance — if you refresh the page, the
          secret is already gone. This ensures that even if the link is later
          discovered, the secret is no longer accessible.
        </p>
      </section>

      <section class="space-y-2">
        <h2 class="text-base font-semibold">What the Server Sees</h2>
        <ul class="list-inside list-disc space-y-1 text-sm text-muted">
          <li>Encrypted ciphertext (opaque bytes it cannot decrypt)</li>
          <li>A claim verifier hash (to authenticate retrieval)</li>
          <li>Expiry time and creation timestamp</li>
        </ul>
        <p class="mt-2 text-sm text-muted">
          The server never sees: your plaintext, encryption keys, passphrases,
          filenames, or any metadata about your secret's content.
        </p>
      </section>

      <section class="space-y-2">
        <h2 class="text-base font-semibold">Open Source</h2>
        <p class="text-sm text-muted">
          The entire codebase — client, server, and cryptographic specification
          — is open source. You can audit the code, run your own instance, or
          verify that our claims are accurate. The protocol specification
          includes test vectors that any implementation must pass.
        </p>
        <p class="text-sm text-muted">
          <a class="link" href="https://github.com/getsecrt/secrt">
            View source on GitHub →
          </a>
        </p>
      </section>

      <a href="/" class="btn btn-primary w-full text-center" onClick={handleHome}>
        Create a secret
      </a>
    </div>
  );
}
