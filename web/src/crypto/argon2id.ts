import type { IArgon2Options } from 'hash-wasm';

type Argon2idFn = (
  options: IArgon2Options & { outputType: 'binary' },
) => Promise<Uint8Array>;

const LOAD_ERROR_PREFIX =
  'Argon2id module failed to load. Refresh and try again.';

let readyFn: Argon2idFn | null = null;
let loadPromise: Promise<Argon2idFn> | null = null;

async function loadArgon2id(): Promise<Argon2idFn> {
  if (readyFn) return readyFn;

  if (!loadPromise) {
    loadPromise = import('hash-wasm/dist/argon2.umd.min.js')
      .then((mod) => {
        const maybeFn =
          (mod as { argon2id?: unknown }).argon2id ??
          (mod as { default?: { argon2id?: unknown } }).default?.argon2id;
        if (typeof maybeFn !== 'function') {
          throw new Error('argon2id export is unavailable');
        }
        readyFn = maybeFn as Argon2idFn;
        return readyFn;
      })
      .catch((err) => {
        loadPromise = null;
        const detail = err instanceof Error ? err.message : String(err);
        throw new Error(`${LOAD_ERROR_PREFIX} (${detail})`);
      });
  }

  return loadPromise;
}

export async function preloadArgon2id(): Promise<void> {
  await loadArgon2id();
}

export async function deriveArgon2id(
  passphrase: string,
  salt: Uint8Array,
  mCost: number,
  tCost: number,
  pCost: number,
  hashLength: number,
): Promise<Uint8Array> {
  const argon2id = await loadArgon2id();
  try {
    return await argon2id({
      password: passphrase,
      salt,
      memorySize: mCost,
      iterations: tCost,
      parallelism: pCost,
      hashLength,
      outputType: 'binary',
    });
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new Error(`Argon2id derivation failed. ${detail}`);
  }
}
