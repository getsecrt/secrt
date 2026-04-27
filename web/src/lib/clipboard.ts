/**
 * Copy sensitive text (secrets, passwords, keys) to the clipboard.
 * In Tauri: uses native clipboard with "exclude from history" flags
 * so the text won't appear in OS clipboard history or cloud sync.
 * On web: falls back to the standard Clipboard API.
 */
export async function copySensitive(text: string): Promise<boolean> {
  if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      await invoke('copy_sensitive', { text });
      return true;
    } catch {
      // Fall through to browser clipboard
    }
  }
  return copyToClipboard(text);
}

/**
 * Copy text to the clipboard via the Clipboard API.
 * Returns `true` on success, `false` on failure.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
