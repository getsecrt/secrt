interface RegisterServiceWorkerOptions {
  isProduction?: boolean;
  nav?: Pick<Navigator, 'serviceWorker'>;
  win?: Pick<Window, 'addEventListener'>;
}

export function registerServiceWorker(
  options: RegisterServiceWorkerOptions = {},
): void {
  const isProduction = options.isProduction ?? import.meta.env.PROD;
  if (!isProduction) return;

  // Skip service worker registration in Tauri — not needed for desktop app
  if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) return;

  const nav = options.nav ?? navigator;
  if (!('serviceWorker' in nav)) return;

  const win = options.win ?? window;
  win.addEventListener('load', () => {
    void nav.serviceWorker
      .register('/sw.js', { scope: '/', updateViaCache: 'none' })
      .catch(() => undefined);
  });
}
