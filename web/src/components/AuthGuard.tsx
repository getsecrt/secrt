import { useEffect } from 'preact/hooks';
import { useAuth } from '../lib/auth-context';
import { navigate } from '../router';

export function AuthGuard({ children }: { children: preact.ComponentChildren }) {
  const auth = useAuth();

  useEffect(() => {
    if (!auth.loading && !auth.authenticated) {
      navigate('/login');
    }
  }, [auth.loading, auth.authenticated]);

  if (auth.loading) {
    return (
      <div class="card text-center">
        <p class="text-sm text-muted">Loading...</p>
      </div>
    );
  }

  if (!auth.authenticated) {
    return null;
  }

  return <>{children}</>;
}
