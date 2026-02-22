import { useEffect } from 'preact/hooks';
import { useAuth } from '../lib/auth-context';
import { navigate } from '../router';

export function AuthGuard({
  children,
}: {
  children: preact.ComponentChildren;
}) {
  const auth = useAuth();

  useEffect(() => {
    if (!auth.loading && !auth.authenticated) {
      // setTimeout avoids Preact effect ordering: child effects fire before
      // parent effects, so navigate() (which dispatches PopStateEvent) would
      // fire before the parent's useRoute listener is attached.
      setTimeout(() => navigate('/login'), 0);
    }
  }, [auth.loading, auth.authenticated]);

  if (auth.loading) {
    return (
      <div class="card text-center">
        <p class="text-muted">Loading...</p>
      </div>
    );
  }

  if (!auth.authenticated) {
    return null;
  }

  return <>{children}</>;
}
