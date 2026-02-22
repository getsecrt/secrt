/**
 * Tauri IPC wrapper for OS keychain (keyring) commands.
 * Service name is hardcoded on the Rust side — the renderer cannot specify it.
 */

async function invoke<T>(cmd: string, args: Record<string, unknown>): Promise<T> {
  const { invoke: tauriInvoke } = await import('@tauri-apps/api/core');
  return tauriInvoke<T>(cmd, args);
}

export async function keyringSet(key: string, value: string): Promise<void> {
  await invoke<void>('keyring_set', { key, value });
}

export async function keyringGet(key: string): Promise<string | null> {
  return invoke<string | null>('keyring_get', { key });
}

export async function keyringDelete(key: string): Promise<void> {
  await invoke<void>('keyring_delete', { key });
}
