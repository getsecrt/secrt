declare module 'hash-wasm/dist/argon2.umd.min.js' {
  import type { IArgon2Options } from 'hash-wasm';

  export function argon2id(options: IArgon2Options): Promise<string | Uint8Array>;

  const _default: {
    argon2id: typeof argon2id;
  };

  export default _default;
}
