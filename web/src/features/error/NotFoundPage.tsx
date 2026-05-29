import { useEffect, useRef, useState } from 'preact/hooks';
import { navigate } from '../../router';
import { CardHeading } from '../../components/CardHeading';

export function NotFoundPage() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [path, setPath] = useState<string>(() =>
    typeof window === 'undefined' ? '' : window.location.pathname,
  );

  useEffect(() => {
    setPath(window.location.pathname);
    const onPop = () => setPath(window.location.pathname);
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const cancel = dissolve404(canvas);
    return cancel;
  }, []);

  const handleHome = (e: MouseEvent) => {
    e.preventDefault();
    navigate('/');
  };

  return (
    <div class="card text-center">
      <canvas
        ref={canvasRef}
        class="block h-32 w-full text-accent sm:h-44"
        role="img"
        aria-label="404 — page not found"
      />
      <CardHeading title="This page does not exist" />

      {path && (
        <p class="mt-1 text-muted">
          <span class="mr-1">No route at</span>
          <code class="code">{path}</code>
        </p>
      )}

      <div class="mt-6 flex flex-wrap justify-center gap-3">
        <a href="/" onClick={handleHome} class="link">
          Home
        </a>
      </div>
    </div>
  );
}

/**
 * Renders `text` as a grid of pixels, then disintegrates them.
 * Inherits color from the canvas's CSS `color`, so theming is free.
 * Returns a cancel function that stops any in-flight animation.
 */
function dissolve404(
  canvas: HTMLCanvasElement,
  {
    text = '404',
    gap = 5,
    duration = 1800,
    stagger = 1500,
    delay = 3000,
  }: {
    text?: string;
    gap?: number;
    duration?: number;
    stagger?: number;
    /** Hold the solid "404" this long before any dot starts dissolving. */
    delay?: number;
  } = {},
): () => void {
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  if (!ctx) return () => {};

  // DPR-aware sizing so the glyphs aren't blurry on retina.
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const cssW = canvas.clientWidth;
  const cssH = canvas.clientHeight;
  if (!cssW || !cssH) return () => {};
  canvas.width = Math.floor(cssW * dpr);
  canvas.height = Math.floor(cssH * dpr);
  ctx.scale(dpr, dpr);
  const w = cssW;
  const h = cssH;

  ctx.fillStyle = '#fff';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  let fs = h * 0.92;
  ctx.font = `800 ${fs}px system-ui, sans-serif`;
  const tw = ctx.measureText(text).width;
  if (tw > w * 0.92) {
    fs = (fs * (w * 0.92)) / tw;
    ctx.font = `800 ${fs}px system-ui, sans-serif`;
  }
  ctx.fillText(text, w / 2, h / 2);

  // Sample alpha on the device-pixel buffer, step in CSS pixels.
  const img = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
  const points: { x: number; y: number; d: number }[] = [];
  for (let y = 0; y < h; y += gap) {
    for (let x = 0; x < w; x += gap) {
      const px = Math.floor(x * dpr);
      const py = Math.floor(y * dpr);
      if (img[(py * canvas.width + px) * 4 + 3] > 128) {
        points.push({ x, y, d: delay + Math.random() * stagger });
      }
    }
  }

  const size = Math.max(1.5, gap * 0.5);
  ctx.fillStyle = getComputedStyle(canvas).color;

  // Reduced motion: render the static 404 and stop.
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) {
    ctx.clearRect(0, 0, w, h);
    for (const p of points) ctx.fillRect(p.x, p.y, size, size);
    return () => {};
  }

  let rafId = 0;
  let start: number | undefined;
  let cancelled = false;
  const frame = (t: number) => {
    if (cancelled) return;
    start ??= t;
    const e = t - start;
    ctx.clearRect(0, 0, w, h);
    let alive = false;
    for (const p of points) {
      const k = (e - p.d) / duration;
      if (k >= 1) continue;
      alive = true;
      ctx.globalAlpha = k < 0 ? 1 : 1 - k;
      ctx.fillRect(p.x, p.y, size, size);
    }
    ctx.globalAlpha = 1;
    if (alive) rafId = requestAnimationFrame(frame);
  };
  rafId = requestAnimationFrame(frame);

  return () => {
    cancelled = true;
    cancelAnimationFrame(rafId);
  };
}
