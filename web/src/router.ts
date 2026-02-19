import { useState, useEffect } from 'preact/hooks';

export type Route =
  | { page: 'send' }
  | { page: 'claim'; id: string }
  | { page: 'how-it-works' }
  | { page: 'privacy' }
  | { page: 'login' }
  | { page: 'register' }
  | { page: 'dashboard' }
  | { page: 'settings' }
  | { page: 'device' }
  | { page: 'theme' }
  | { page: 'not-found' };

export function matchRoute(path: string): Route {
  if (path === '/' || path === '') {
    return { page: 'send' };
  }

  const match = path.match(/^\/s\/([a-zA-Z0-9_-]+)\/?$/);
  if (match) {
    return { page: 'claim', id: match[1] };
  }

  if (path === '/how-it-works') {
    return { page: 'how-it-works' };
  }

  if (path === '/privacy') {
    return { page: 'privacy' };
  }

  if (path === '/login') {
    return { page: 'login' };
  }

  if (path === '/register') {
    return { page: 'register' };
  }

  if (path === '/dashboard') {
    return { page: 'dashboard' };
  }

  if (path === '/settings') {
    return { page: 'settings' };
  }

  if (path === '/device') {
    return { page: 'device' };
  }

  if (import.meta.env.DEV) {
    if (path === '/test/theme') {
      return { page: 'theme' };
    }
  }

  return { page: 'not-found' };
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() =>
    matchRoute(window.location.pathname),
  );

  useEffect(() => {
    // Prevent browser from trying to restore scroll position in SPA —
    // content is dynamically rendered so browser restoration is unreliable.
    if ('scrollRestoration' in history) {
      history.scrollRestoration = 'manual';
    }

    const onPopState = () => {
      setRoute(matchRoute(window.location.pathname));
    };

    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  return route;
}

export function navigate(path: string): void {
  window.history.pushState(null, '', path);
  window.scrollTo(0, 0);
  window.dispatchEvent(new PopStateEvent('popstate'));
}
