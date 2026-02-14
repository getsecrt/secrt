import { CheckCircleIcon } from '../../components/Icons';
import { CopyButton } from '../../components/CopyButton';
import { ClipboardIcon } from '../../components/Icons';
import { formatExpiryDate } from '../../lib/ttl';

interface ShareResultProps {
  shareUrl: string;
  expiresAt: string;
  onReset: () => void;
}

export function ShareResult({
  shareUrl,
  expiresAt,
  onReset,
}: ShareResultProps) {
  return (
    <div class="card space-y-5">
      <div class="flex flex-col items-center gap-2 text-center">
        <CheckCircleIcon class="size-10 text-success" />
        <h2 class="text-lg font-semibold">Secret Created</h2>
      </div>

      <div class="rounded-md border border-border bg-surface px-3 py-2.5 inset-shadow-sm">
        <pre
          class="font-mono text-sm break-all whitespace-pre-wrap select-all"
          role="textbox"
          aria-label="Share URL"
          data-testid="share-url"
        >
          {shareUrl}
        </pre>
      </div>

      <CopyButton
        text={shareUrl}
        icon={<ClipboardIcon class="size-5" />}
        class="btn btn-primary w-full tracking-wider uppercase"
        label="Copy Link"
      />

      <p class="text-center text-xs text-muted">
        Expires {formatExpiryDate(expiresAt)}. This link works exactly once.
      </p>

      <button type="button" class="link mx-auto block" onClick={onReset}>
        Send Another Secret
      </button>
    </div>
  );
}
