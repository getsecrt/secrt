import { CheckCircleIcon } from '../../components/Icons';
import { CopyButton } from '../../components/CopyButton';
import { formatExpiryDate } from '../../lib/ttl';

interface ShareResultProps {
  shareUrl: string;
  expiresAt: string;
  onReset: () => void;
}

export function ShareResult({ shareUrl, expiresAt, onReset }: ShareResultProps) {
  return (
    <div class="card space-y-5">
      <div class="flex flex-col items-center gap-2 text-center">
        <CheckCircleIcon class="size-10 text-success" />
        <h2 class="text-lg font-semibold">Secret created</h2>
      </div>

      <div class="rounded-md border border-border bg-surface-raised px-3 py-2.5">
        <p
          class="select-all break-all font-mono text-sm"
          role="textbox"
          aria-label="Share URL"
        >
          {shareUrl}
        </p>
      </div>

      <CopyButton text={shareUrl} class="btn-primary w-full" label="Copy link" />

      <p class="text-center text-xs text-muted">
        Expires {formatExpiryDate(expiresAt)}. This link works exactly once.
      </p>

      <button
        type="button"
        class="btn w-full"
        onClick={onReset}
      >
        Create another
      </button>
    </div>
  );
}
