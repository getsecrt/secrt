/**
 * Tiered, visibility-aware polling for the pair flow.
 *
 *   1 s  for the first 10 s   — most pairs complete fast
 *   2 s  for the next 50 s
 *   5 s  thereafter
 *   pauses while document.visibilityState === 'hidden'
 *
 * The handler returns `true` to stop the loop (terminal state reached).
 * The hook reschedules itself only after the current poll resolves, so a
 * slow response can't fan out into overlapping requests.
 */

import { useEffect, useRef } from 'preact/hooks';

export type PollHandler = (signal: AbortSignal) => Promise<boolean>;

export function nextPollDelayMs(elapsedMs: number): number {
  if (elapsedMs < 10_000) return 1_000;
  if (elapsedMs < 60_000) return 2_000;
  return 5_000;
}

interface Options {
  /** Set to false to suspend the loop (e.g. while showing an approval modal). */
  enabled?: boolean;
}

export function usePairPolling(handler: PollHandler, opts: Options = {}): void {
  const { enabled = true } = opts;
  const handlerRef = useRef(handler);
  handlerRef.current = handler;

  useEffect(() => {
    if (!enabled) return;

    let cancelled = false;
    const startedAt = Date.now();
    const controller = new AbortController();
    let timeout: ReturnType<typeof setTimeout> | null = null;
    let visible = document.visibilityState === 'visible';

    const tick = async () => {
      if (cancelled) return;
      if (!visible) {
        // Re-arm short — visibilitychange will trigger an immediate tick
        // when the tab returns; this is just a safety net.
        timeout = setTimeout(tick, 1_000);
        return;
      }
      try {
        const stop = await handlerRef.current(controller.signal);
        if (cancelled || stop) return;
      } catch {
        // Network blips: fall through to the next scheduled tick.
      }
      if (cancelled) return;
      const delay = nextPollDelayMs(Date.now() - startedAt);
      timeout = setTimeout(tick, delay);
    };

    const onVisible = () => {
      const wasVisible = visible;
      visible = document.visibilityState === 'visible';
      if (!wasVisible && visible && !cancelled) {
        if (timeout) clearTimeout(timeout);
        timeout = setTimeout(tick, 0);
      }
    };
    document.addEventListener('visibilitychange', onVisible);

    // First poll fires immediately so the displayer-as-receiver doesn't
    // wait a full second before discovering an already-approved slot
    // (rare but possible — e.g. approve raced an early refresh).
    timeout = setTimeout(tick, 0);

    return () => {
      cancelled = true;
      if (timeout) clearTimeout(timeout);
      controller.abort();
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [enabled]);
}
