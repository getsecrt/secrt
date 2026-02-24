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
 * Copy text to the clipboard. Uses the Clipboard API with an
 * execCommand('copy') fallback for older browsers.
 * Returns `true` on success, `false` on total failure.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for older browsers
    try {
      const el = document.createElement('textarea');
      el.value = text;
      el.style.position = 'fixed';
      el.style.opacity = '0';
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
      return true;
    } catch {
      return false;
    }
  }
}
