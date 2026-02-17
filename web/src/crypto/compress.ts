import { init, compress as zstdCompress } from '@bokuweb/zstd-wasm';

let ready = false;
let initPromise: Promise<void> | null = null;

/** Lazily initialize the zstd WASM module. Safe to call multiple times. */
export async function ensureCompressor(): Promise<void> {
  if (ready) return;
  if (!initPromise) {
    initPromise = init().then(() => {
      ready = true;
    });
  }
  await initPromise;
}

/** Compress data with zstd at level 3. Call ensureCompressor() first. */
export function compress(data: Uint8Array): Uint8Array {
  if (!ready)
    throw new Error(
      'compressor not initialized — call ensureCompressor() first',
    );
  return zstdCompress(data, 3);
}
