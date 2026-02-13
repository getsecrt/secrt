import { useEffect, useMemo, useState } from 'preact/hooks';
import {
  base64UrlToBytes,
  bytesToBase64Url,
  deriveAuthAndEncFromRoot,
  fetchInfo,
  fetchSession,
  formatLocalApiKey,
  generateRootKey,
  logout,
  passkeyLoginFinish,
  passkeyLoginStart,
  passkeyRegisterFinish,
  passkeyRegisterStart,
  registerApiKey
} from './lib/api';

type InfoState =
  | { status: 'loading' }
  | { status: 'ready'; ttlDefault: number; ttlMax: number; authenticated: boolean }
  | { status: 'error'; message: string };

type SessionState = {
  authenticated: boolean;
  userId: number | null;
  handle: string | null;
  expiresAt: string | null;
};

const SESSION_STORAGE_KEY = 'secrt-session-token';

const emptySession: SessionState = {
  authenticated: false,
  userId: null,
  handle: null,
  expiresAt: null
};

function supportsWebAuthn(): boolean {
  return typeof window !== 'undefined' && typeof window.PublicKeyCredential !== 'undefined';
}

async function runWebAuthnRegister(
  challengeB64: string,
  handle: string,
  displayName: string
): Promise<string | null> {
  if (!supportsWebAuthn()) {
    return null;
  }

  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: base64UrlToBytes(challengeB64),
      rp: {
        id: window.location.hostname,
        name: 'secrt'
      },
      user: {
        id: new TextEncoder().encode(handle),
        name: handle,
        displayName
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      timeout: 60_000,
      attestation: 'none'
    }
  })) as PublicKeyCredential | null;

  if (!credential) {
    return null;
  }
  return bytesToBase64Url(new Uint8Array(credential.rawId));
}

async function runWebAuthnLogin(challengeB64: string, credentialId: string): Promise<string | null> {
  if (!supportsWebAuthn()) {
    return null;
  }

  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: base64UrlToBytes(challengeB64),
      allowCredentials: [
        {
          type: 'public-key',
          id: base64UrlToBytes(credentialId)
        }
      ],
      timeout: 60_000,
      userVerification: 'preferred'
    }
  })) as PublicKeyCredential | null;

  if (!assertion) {
    return null;
  }
  return bytesToBase64Url(new Uint8Array(assertion.rawId));
}

export function App() {
  const [info, setInfo] = useState<InfoState>({ status: 'loading' });
  const [sessionToken, setSessionToken] = useState<string>('');
  const [session, setSession] = useState<SessionState>(emptySession);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string>('');
  const [error, setError] = useState<string>('');

  const [displayName, setDisplayName] = useState('secrt user');
  const [handle, setHandle] = useState('user');
  const [credentialId, setCredentialId] = useState('');

  const [generatedKey, setGeneratedKey] = useState('');
  const [generatedEncKey, setGeneratedEncKey] = useState('');

  const hasSession = useMemo(() => sessionToken.trim().length > 0, [sessionToken]);

  useEffect(() => {
    const controller = new AbortController();
    fetchInfo(controller.signal)
      .then((result) => {
        setInfo({
          status: 'ready',
          ttlDefault: result.ttl.default_seconds,
          ttlMax: result.ttl.max_seconds,
          authenticated: result.authenticated
        });
      })
      .catch((err: unknown) => {
        setInfo({
          status: 'error',
          message: err instanceof Error ? err.message : 'unknown error'
        });
      });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    const stored = window.localStorage.getItem(SESSION_STORAGE_KEY) ?? '';
    if (stored.trim()) {
      setSessionToken(stored.trim());
    }
  }, []);

  useEffect(() => {
    if (!hasSession) {
      setSession(emptySession);
      return;
    }
    fetchSession(sessionToken)
      .then((next) => {
        setSession({
          authenticated: next.authenticated,
          userId: next.user_id,
          handle: next.handle,
          expiresAt: next.expires_at
        });
      })
      .catch(() => {
        setSession(emptySession);
      });
  }, [hasSession, sessionToken]);

  const setSessionAndPersist = (token: string) => {
    const trimmed = token.trim();
    setSessionToken(trimmed);
    if (trimmed) {
      window.localStorage.setItem(SESSION_STORAGE_KEY, trimmed);
    } else {
      window.localStorage.removeItem(SESSION_STORAGE_KEY);
    }
  };

  const clearMessages = () => {
    setNotice('');
    setError('');
  };

  const runAction = async (fn: () => Promise<void>) => {
    if (busy) {
      return;
    }
    setBusy(true);
    clearMessages();
    try {
      await fn();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'operation failed');
    } finally {
      setBusy(false);
    }
  };

  const registerPasskey = () =>
    runAction(async () => {
      const desiredHandle = handle.trim() || `user-${Date.now()}`;
      const desiredDisplay = displayName.trim() || desiredHandle;
      const start = await passkeyRegisterStart(desiredDisplay, desiredHandle);
      const webauthnId = await runWebAuthnRegister(start.challenge, desiredHandle, desiredDisplay);
      const finalCredentialId =
        webauthnId ?? (credentialId.trim() || `cred-${Date.now().toString(36)}`);

      const finish = await passkeyRegisterFinish(
        start.challenge_id,
        finalCredentialId,
        `webauthn:${finalCredentialId}`
      );
      setCredentialId(finalCredentialId);
      setSessionAndPersist(finish.session_token);
      setNotice(`Passkey registered. Session active for ${finish.handle}.`);
    });

  const loginWithPasskey = () =>
    runAction(async () => {
      const requestedCredential = credentialId.trim();
      if (!requestedCredential) {
        throw new Error('credential_id is required for login');
      }

      const start = await passkeyLoginStart(requestedCredential);
      const webauthnId = await runWebAuthnLogin(start.challenge, requestedCredential);
      const finalCredentialId = webauthnId ?? requestedCredential;

      const finish = await passkeyLoginFinish(start.challenge_id, finalCredentialId);
      setSessionAndPersist(finish.session_token);
      setNotice(`Logged in as ${finish.handle}.`);
    });

  const logoutSession = () =>
    runAction(async () => {
      if (!sessionToken) {
        return;
      }
      await logout(sessionToken);
      setSessionAndPersist('');
      setGeneratedKey('');
      setGeneratedEncKey('');
      setNotice('Logged out.');
    });

  const registerClientGeneratedKey = () =>
    runAction(async () => {
      if (!sessionToken) {
        throw new Error('log in first');
      }
      const root = generateRootKey();
      const { authToken, encKey } = await deriveAuthAndEncFromRoot(root);
      const response = await registerApiKey(sessionToken, bytesToBase64Url(authToken));
      setGeneratedKey(formatLocalApiKey(response.prefix, root));
      setGeneratedEncKey(bytesToBase64Url(encKey));
      setNotice('Created new local sk2_ key. Save it now: it is not persisted server-side.');
    });

  return (
    <main className="shell">
      <section className="card">
        <p className="eyebrow">secrt alpha</p>
        <h1>Passkey session + client-generated API keys</h1>
        <p className="lede">
          This page is intentionally minimal for operability testing of WebAuthn sessions and
          zero-knowledge API key registration.
        </p>

        {info.status === 'loading' && <p className="state">Loading API capabilities...</p>}
        {info.status === 'error' && <p className="state error">API unavailable: {info.message}</p>}
        {info.status === 'ready' && (
          <dl className="facts">
            <div>
              <dt>Server authenticated</dt>
              <dd>{info.authenticated ? 'yes' : 'no'}</dd>
            </div>
            <div>
              <dt>Default TTL</dt>
              <dd>{info.ttlDefault}s</dd>
            </div>
            <div>
              <dt>Max TTL</dt>
              <dd>{info.ttlMax}s</dd>
            </div>
          </dl>
        )}

        <section className="panel">
          <h2>Passkey</h2>
          <p className="panel-text">
            {supportsWebAuthn()
              ? 'WebAuthn is available in this browser.'
              : 'WebAuthn unavailable here; server flow still works with manual credential id.'}
          </p>
          <div className="form-grid">
            <label>
              display_name
              <input
                value={displayName}
                onInput={(e) => setDisplayName((e.target as HTMLInputElement).value)}
                placeholder="secrt user"
              />
            </label>
            <label>
              handle
              <input
                value={handle}
                onInput={(e) => setHandle((e.target as HTMLInputElement).value)}
                placeholder="user"
              />
            </label>
            <label>
              credential_id
              <input
                value={credentialId}
                onInput={(e) => setCredentialId((e.target as HTMLInputElement).value)}
                placeholder="base64url credential id"
              />
            </label>
          </div>
          <div className="actions">
            <button type="button" disabled={busy} onClick={registerPasskey}>
              Register Passkey
            </button>
            <button type="button" disabled={busy} onClick={loginWithPasskey}>
              Login
            </button>
            <button type="button" disabled={busy || !sessionToken} onClick={logoutSession}>
              Logout
            </button>
          </div>
        </section>

        <section className="panel">
          <h2>Session</h2>
          <dl className="mini-facts">
            <div>
              <dt>Authenticated</dt>
              <dd>{session.authenticated ? 'yes' : 'no'}</dd>
            </div>
            <div>
              <dt>User</dt>
              <dd>{session.handle ?? 'none'}</dd>
            </div>
            <div>
              <dt>Expires</dt>
              <dd>{session.expiresAt ?? 'n/a'}</dd>
            </div>
          </dl>
        </section>

        <section className="panel">
          <h2>Register API Key</h2>
          <p className="panel-text">
            Generates a new 32-byte root key client-side, derives auth/encryption keys with
            WebCrypto HKDF, and registers only the derived auth token.
          </p>
          <div className="actions">
            <button type="button" disabled={busy || !session.authenticated} onClick={registerClientGeneratedKey}>
              Create Local sk2_ Key
            </button>
          </div>
          {generatedKey && (
            <div className="result">
              <label>
                local_api_key
                <textarea readOnly value={generatedKey} rows={3} />
              </label>
              <label>
                enc_key_b64
                <textarea readOnly value={generatedEncKey} rows={2} />
              </label>
            </div>
          )}
        </section>

        {notice && <p className="state ok">{notice}</p>}
        {error && <p className="state error">{error}</p>}
      </section>
    </main>
  );
}
