import { encode } from 'uqr';
import { useEffect, useRef } from 'preact/hooks';
import {
  CheckCircleIcon,
  ClipboardIcon,
  ShareFromSquareIcon,
} from '../../components/Icons';
import { CopyButton } from '../../components/CopyButton';
import { formatExpiryDate } from '../../lib/ttl';
import { CardHeading } from '../../components/CardHeading';

interface QrCanvasProps {
  url: string;
  size?: number;
}

function QrCanvas({ url, size = 192 }: QrCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const qr = encode(url);
    const modules = qr.size;
    const dpr = window.devicePixelRatio || 1;
    const px = Math.floor((size * dpr) / modules);
    const dim = px * modules;

    canvas.width = dim;
    canvas.height = dim;
    canvas.style.width = `${size}px`;
    canvas.style.height = `${size}px`;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const dark = document.documentElement.classList.contains('dark');

    ctx.fillStyle = dark ? '#000' : '#fff';
    ctx.fillRect(0, 0, dim, dim);
    ctx.fillStyle = dark ? '#fff' : '#000';

    for (let y = 0; y < modules; y++) {
      for (let x = 0; x < modules; x++) {
        if (qr.data[y][x]) {
          ctx.fillRect(x * px, y * px, px, px);
        }
      }
    }
  }, [url, size]);

  return (
    <canvas
      ref={canvasRef}
      aria-label="QR code for share URL"
      role="img"
      class="rounded-lg"
    />
  );
}

interface ShareResultProps {
  shareUrl: string;
  expiresAt: string;
  onReset?: () => void;
  title?: string;
  subtitle?: string;
  resetLabel?: string;
  /** Skip the outer card wrapper (e.g. when rendered inside a modal). */
  bare?: boolean;
}

export function ShareResult({
  shareUrl,
  expiresAt,
  onReset,
  title = 'Secret Created',
  subtitle,
  resetLabel = 'Send Another Secret',
  bare = false,
}: ShareResultProps) {
  return (
    <div class={bare ? 'space-y-5' : 'card space-y-5'}>
      <CardHeading
        title={title}
        subtitle={subtitle}
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

      <div class="flex gap-4">
        <CopyButton
          text={shareUrl}
          icon={<ClipboardIcon class="size-5" />}
          class="w-full"
          label={
            <>
              Copy<span class="hidden xs:inline">&nbsp;Link</span>
            </>
          }
        />

        {!!navigator.share && (
          <button
            type="button"
            class="btn btn-primary w-full tracking-wider uppercase"
            onClick={() => {
              navigator.share({
                title: "You've been sent a secret",
                url: shareUrl,
              });
            }}
          >
            <ShareFromSquareIcon class="size-5" />
            Share<span class="hidden xs:inline">&nbsp;Link</span>
          </button>
        )}
      </div>

      <div class="mt-7 flex justify-center">
        <QrCanvas url={shareUrl} />
      </div>

      <div>
        <p class="mb-1 text-center text-sm">
          Expires {formatExpiryDate(expiresAt)}
        </p>

        <p class="text-center text-sm text-muted">This link only works once.</p>
      </div>

      {onReset && (
        <button type="button" class="link mx-auto block" onClick={onReset}>
          {resetLabel}
        </button>
      )}
    </div>
  );
}
