import { useState, useEffect } from 'preact/hooks';

export type Route =
  | { page: 'send' }
  | { page: 'claim'; id: string }
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

  if (path === '/test/theme') {
    return { page: 'theme' };
  }

  return { page: 'not-found' };
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() =>
    matchRoute(window.location.pathname),
  );

  useEffect(() => {
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
  window.dispatchEvent(new PopStateEvent('popstate'));
}
