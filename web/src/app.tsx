import { useEffect, useState } from 'preact/hooks';
import { fetchInfo } from './lib/api';

type LoadState =
  | { status: 'loading' }
  | { status: 'ready'; ttlDefault: number; ttlMax: number; authenticated: boolean }
  | { status: 'error'; message: string };

export function App() {
  const [state, setState] = useState<LoadState>({ status: 'loading' });

  useEffect(() => {
    const controller = new AbortController();

    fetchInfo(controller.signal)
      .then((info) => {
        setState({
          status: 'ready',
          ttlDefault: info.ttl.default_seconds,
          ttlMax: info.ttl.max_seconds,
          authenticated: info.authenticated
        });
      })
      .catch((err: unknown) => {
        setState({
          status: 'error',
          message: err instanceof Error ? err.message : 'unknown error'
        });
      });

    return () => controller.abort();
  }, []);

  return (
    <main className="shell">
      <section className="card">
        <p className="eyebrow">secrt</p>
        <h1>Zero-knowledge one-time secret sharing</h1>
        <p className="lede">
          This Preact app is the web foundation shared between browser deployment and future Tauri packaging.
        </p>

        {state.status === 'loading' && <p className="state">Loading API capabilities...</p>}

        {state.status === 'error' && (
          <p className="state error">API unavailable: {state.message}</p>
        )}

        {state.status === 'ready' && (
          <dl className="facts">
            <div>
              <dt>Authenticated</dt>
              <dd>{state.authenticated ? 'yes' : 'no'}</dd>
            </div>
            <div>
              <dt>Default TTL</dt>
              <dd>{state.ttlDefault}s</dd>
            </div>
            <div>
              <dt>Max TTL</dt>
              <dd>{state.ttlMax}s</dd>
            </div>
          </dl>
        )}
      </section>
    </main>
  );
}
