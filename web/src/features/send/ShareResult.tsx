import { CheckCircleIcon } from '../../components/Icons';
import { CopyButton } from '../../components/CopyButton';
import { ClipboardIcon } from '../../components/Icons';
import { formatExpiryDate } from '../../lib/ttl';
import { CardHeading } from '../../components/CardHeading';

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
      <CardHeading
        title="Secret Created"
        icon={<CheckCircleIcon class="size-10 text-success" />}
      />

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
        class="w-full"
        label="Copy Link"
      />

      <div>
        <p class="mb-1 text-center text-sm">
          Expires {formatExpiryDate(expiresAt)}
        </p>

        <p class="text-center text-sm text-muted">This link only works once.</p>
      </div>

      <button type="button" class="link mx-auto block" onClick={onReset}>
        Send Another Secret
      </button>
    </div>
  );
}
