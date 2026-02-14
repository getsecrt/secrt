import { navigate } from '../router';

export function HowItWorks() {
  const handleLearnMore = (e: MouseEvent) => {
    e.preventDefault();
    navigate('/how-it-works');
  };

  return (
    <details class="group rounded-lg border border-border bg-surface px-4 py-3">
      <summary class="cursor-pointer select-none text-sm font-medium text-muted hover:text-text">
        How does secrt keep my data safe?
      </summary>
      <div class="mt-3 space-y-2 text-sm text-muted">
        <p>
          Your secret is encrypted in your browser using AES-256-GCM before it
          ever leaves your device. The decryption key is embedded in the share
          link's fragment, which is never sent to the server. The server only
          stores ciphertext it cannot read.
        </p>
        <p>
          Each secret can only be retrieved once — after that, it's permanently
          deleted.
        </p>
        <p>
          <a href="/how-it-works" class="link" onClick={handleLearnMore}>
            Full technical details →
          </a>
        </p>
      </div>
    </details>
  );
}
