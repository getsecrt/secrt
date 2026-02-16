import { navigate } from '../router';

/** Inline brand mark — matches the SVG logo color scheme. */
export function Brand() {
  return (
    <span class="text-black dark:text-white">
      s<span class="text-green-700 dark:text-green-400">e</span>crt
    </span>
  );
}

export function FaqSection() {
  return (
    <section class="space-y-6">
      <h2 class="heading text-center">Frequently Asked Questions</h2>

      <section class="space-y-2">
        <h3 class="text-xl font-semibold">
          Can <Brand /> read my secrets?
        </h3>
        <p class="">
          No. Your secret is encrypted on your device before it reaches our
          server. The key that unlocks it lives only in the share link you send
          — we never see it. Even if our database were stolen, the attacker
          would get only scrambled data with no way to decrypt it.
        </p>
      </section>

      <section class="space-y-2">
        <h3 class="text-xl font-semibold">
          What if someone intercepts the link?
        </h3>
        <p class="">
          A secret can only be opened once. If someone else opens it first, the
          intended recipient will see that the secret is gone, so you'll know it
          was intercepted.
        </p>
        <p class="">
          For extra protection, add a passphrase. The recipient will need both
          the link <em>and</em> the passphrase to decrypt. Send the passphrase
          through a different channel, like a phone call. That way, an
          intercepted link alone is useless.
        </p>
      </section>

      <section class="space-y-2">
        <h3 class="text-xl font-semibold">
          How can I trust you to keep my data safe?
        </h3>
        <p class="">
          You don't have to trust us — <Brand /> is designed so that trust isn't
          required. Your data is encrypted on your device before it ever reaches
          our server, and the decryption key is never sent to the server. We
          also mask IP addresses and strip identifying information from logs, so
          we can't tell who sent what.
        </p>
        <p class="">
          The entire codebase — client, server, and cryptographic specification
          — is{' '}
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
          browser's developer tools, watch the Network tab, and confirm that no
          plaintext or encryption keys ever leave your device.
        </p>
        <p class="">
          That said, trusting JavaScript served by a website is inherently
          difficult; the code could change between visits, and browser
          extensions or network middleboxes could modify it. This is a known
          limitation of any web-based encryption tool, not just <Brand />.
        </p>
        <p class="">
          For highly sensitive data or automation, we also provide a
          command-line interface (CLI) that is fully interoperable with the web
          version. CLI binaries are Apple-notarized on macOS and signed via
          Azure Trusted Signing on Windows, and every release includes SHA-256
          checksums so you can verify the download hasn't been tampered with.
          The CLI offers the strongest security guarantees because there's no
          runtime code loading and no browser in the loop.
        </p>
      </section>

      <section class="space-y-2">
        <h3 class="text-xl font-semibold">
          What happens after my secret is opened?
        </h3>
        <p class="">
          It's permanently deleted — instantly and automatically. There's no
          copy on the server, no backup, no way for anyone (including us) to
          recover it. If the link is visited again, it will show that the secret
          no longer exists.
        </p>
      </section>
    </section>
  );
}

export function HowItWorksLink() {
  const handleLearnMore = (e: MouseEvent) => {
    e.preventDefault();
    navigate('/how-it-works');
  };

  return (
    <p class="px-1 text-center">
      <a href="/how-it-works" class="link" onClick={handleLearnMore}>
        How <Brand /> Works →
      </a>
    </p>
  );
}
