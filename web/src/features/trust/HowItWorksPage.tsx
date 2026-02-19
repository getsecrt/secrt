import { CardHeading } from '../../components/CardHeading';
import { navigate } from '../../router';

export function HowItWorksPage() {
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
          title="How secrt Works"
          subtitle="An overview of our zero-knowledge architecture"
          underline
        />

        <section class="space-y-2">
          <h2 class="text-xl font-semibold text-black dark:text-white">
            Overview
          </h2>
          <p class="">
            <Secrt /> is a zero-knowledge, one-time secret sharing service. Your
            data is encrypted entirely in your browser before being sent to the
            server. The server stores only ciphertext — it never has access to
            your plaintext, decryption keys, or passphrases.
          </p>
        </section>

        <section class="space-y-2">
          <h2 class="text-xl font-semibold text-black dark:text-white">
            Encryption
          </h2>
          <p class="">
            When you create a secret, your browser generates a random 256-bit
            key and encrypts your content using <strong>AES-256-GCM</strong> —
            the same authenticated encryption standard used by governments and
            financial institutions. Key derivation uses{' '}
            <strong>HKDF-SHA-256</strong> to produce separate encryption and
            claim verification keys from a single root key.
          </p>
          <p class="">
            The encryption key is embedded in the share link's URL fragment (the
            part after{' '}
            <code class="rounded bg-surface-raised px-1 py-0.5 text-xs">#</code>
            ). Fragments are never sent to the server by browsers, so the server
            never sees your key.
          </p>
        </section>

        <section class="space-y-2">
          <h2 class="text-xl font-semibold text-black dark:text-white">
            Passphrase Protection
          </h2>
          <p class="">
            For extra security, you can set a passphrase. This uses{' '}
            <strong>Argon2id</strong> (memory-hard key derivation) to derive a
            secondary key. The final encryption key is then derived from both
            the URL key and the passphrase key combined. Even if someone
            intercepts the share link, they cannot decrypt the secret without
            the passphrase.
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
            The entire codebase — client, server, and cryptographic
            specification — is open source. You can audit the code, run your own
            instance, or verify that our claims are accurate. The protocol
            specification includes test vectors that any implementation must
            pass.
          </p>
          <p class="">
            <a class="link" href="https://github.com/getsecrt/secrt">
              View source on GitHub →
            </a>
          </p>
        </section>
      </div>

      <div class="card space-y-8 bg-white/20 dark:bg-black/20">
        <CardHeading title="Frequently Asked Questions" underline />

        <section class="space-y-2">
          <h3 class="text-xl font-semibold text-black dark:text-white">
            What is your privacy policy?
          </h3>
          <p class="">
            We have a strict{' '}
            <a
              class="link"
              href="/privacy"
              onClick={(e: MouseEvent) => {
                e.preventDefault();
                navigate('/privacy');
              }}
            >
              privacy policy
            </a>{' '}
            emphasizing our complete inability to read your data and limit
            identifiable information as much as possible. Read it at{' '}
            <a
              class="link"
              href="/privacy"
              onClick={(e: MouseEvent) => {
                e.preventDefault();
                navigate('/privacy');
              }}
            >
              {location.origin}/privacy
            </a>
            .
          </p>
        </section>

        <section class="space-y-2">
          <h3 class="text-xl font-semibold text-black dark:text-white">
            Can{' '}
            <span class="text-black dark:text-white">
              s<span class="text-green-700 dark:text-green-400">e</span>crt
            </span>{' '}
            read my secrets?
          </h3>
          <p class="">
            No. Your secret is encrypted on your device before it reaches our
            server. The key that unlocks it lives only in the share link you
            send — we never see it. Even if our database were stolen, the
            attacker would get only scrambled data with no way to decrypt it.
          </p>
        </section>

        <section class="space-y-2">
          <h3 class="text-xl font-semibold text-black dark:text-white">
            What if someone intercepts the link?
          </h3>
          <p class="">
            A secret can only be opened once. If someone else opens it first,
            the intended recipient will see that the secret is gone, so you'll
            know it was intercepted.
          </p>
          <p class="">
            For extra protection, add a passphrase. The recipient will need both
            the link <em>and</em> the passphrase to decrypt. Send the passphrase
            through a different channel, like a phone call. That way, an
            intercepted link alone is useless.
          </p>
        </section>

        <section class="space-y-2">
          <h3 class="text-xl font-semibold text-black dark:text-white">
            How can I trust you to keep my data safe?
          </h3>
          <p class="">
            You don't have to trust us — <Secrt /> is designed so that trust
            isn't required. Your data is encrypted on your device before it ever
            reaches our server, and the decryption key is never sent to the
            server. We also mask IP addresses and strip identifying information
            from logs, so we can't tell who sent what.
          </p>
          <p class="">
            The entire codebase — client, server, and cryptographic
            specification — is{' '}
            <a
              class="link"
              href="https://github.com/getsecrt/secrt"
              target="_blank"
              rel="noopener noreferrer"
            >
              open source on GitHub
            </a>
            . Anyone can audit the code or run their own instance. The protocol
            includes published test vectors so independent implementations can
            verify correctness without reading our code.
          </p>
          <p class="">
            You can verify the zero-knowledge property yourself: open your
            browser's developer tools, watch the Network tab, and confirm that
            no plaintext or encryption keys ever leave your device.
          </p>
          <p class="">
            That said, trusting JavaScript served by a website is inherently
            difficult; the code could change between visits, and browser
            extensions or network middleboxes could modify it. This is a known
            limitation of any web-based encryption tool, not just <Secrt />.
          </p>
          <p class="">
            For highly sensitive data or automation, we also provide a
            command-line interface (CLI) that is fully interoperable with the
            web version. CLI binaries are Apple-notarized on macOS and signed
            via Azure Trusted Signing on Windows, and every release includes
            SHA-256 checksums so you can verify the download hasn't been
            tampered with. The CLI offers the strongest security guarantees
            because there's no runtime code loading and no browser in the loop.
          </p>
        </section>

        <section class="space-y-2">
          <h3 class="text-xl font-semibold text-black dark:text-white">
            What happens after my secret is opened?
          </h3>
          <p class="">
            It's permanently deleted — instantly and automatically. There's no
            copy on the server, no backup, no way for anyone (including us) to
            recover it. If the link is visited again, it will show that the
            secret no longer exists.
          </p>
        </section>
      </div>

      <div class="card space-y-8 bg-white/20 dark:bg-black/20">
        <section class="space-y-2">
          <CardHeading title="Technical Whitepaper" underline />
          <p class="">
            For an in depth analysis of the architecture of <Secrt />, please
            refer to the{' '}
            <a
              class="link"
              href="https://github.com/getsecrt/secrt/blob/main/docs/whitepaper.md"
            >
              secrt technical whitepaper
            </a>{' '}
            on GitHub.
          </p>
        </section>
      </div>

      <div class="text-center">
        <a href="/" class="link" onClick={handleHome}>
          Home
        </a>
      </div>
    </div>
  );
}
