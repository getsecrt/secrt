import { createContext } from 'preact';
import { useState, useEffect, useCallback, useContext } from 'preact/hooks';
import type { ComponentChildren } from 'preact';
import {
  getSessionToken,
  getSessionTokenSync,
  setSessionToken,
  clearSessionToken,
  getCachedProfileSync,
  setCachedProfile,
} from './session';
import { isTauri } from './config';
import { fetchSession, logout as apiLogout } from './api';

export interface AuthState {
  loading: boolean;
  authenticated: boolean;
  userId: string | null;
  displayName: string | null;
  sessionToken: string | null;
  login: (token: string, userId: string, displayName: string) => void;
  logout: () => Promise<void>;
  setDisplayName: (name: string) => void;
}

const defaultState: AuthState = {
  loading: true,
  authenticated: false,
  userId: null,
  displayName: null,
  sessionToken: null,
  login: () => {},
  logout: async () => {},
  setDisplayName: () => {},
};

const AuthContext = createContext<AuthState>(defaultState);

export function AuthProvider({ children }: { children: ComponentChildren }) {
  // Read cached auth state synchronously for browser (avoids flash of wrong UI).
  // In Tauri mode, start with loading: true and resolve via useEffect (keyring is async).
  const [cached] = useState(() => {
    if (isTauri()) return { token: null as string | null, profile: null };
    const token = getSessionTokenSync();
    const profile = token ? getCachedProfileSync() : null;
    return { token, profile };
  });

  const [loading, setLoading] = useState(
    isTauri() ? true : !!cached.token && !cached.profile,
  );
  const [authenticated, setAuthenticated] = useState(!!cached.profile);
  const [userId, setUserId] = useState<string | null>(
    cached.profile?.userId ?? null,
  );
  const [displayName, setDisplayName] = useState<string | null>(
    cached.profile?.displayName ?? null,
  );
  const [sessionToken, setToken] = useState<string | null>(
    cached.profile ? cached.token : null,
  );

  // Validate the session in the background
  useEffect(() => {
    let cancelled = false;

    (async () => {
      const token = await getSessionToken();
      if (!token) {
        if (!cancelled) setLoading(false);
        return;
      }

      try {
        const res = await fetchSession(token);
        if (cancelled) return;
        if (res.authenticated && res.user_id && res.display_name) {
          setToken(token);
          setAuthenticated(true);
          setUserId(res.user_id);
          setDisplayName(res.display_name);
          setCachedProfile({
            userId: res.user_id,
            displayName: res.display_name,
          });
        } else {
          await clearSessionToken();
          setAuthenticated(false);
          setToken(null);
          setUserId(null);
          setDisplayName(null);
        }
      } catch {
        // Network error or aborted request — don't clear the token.
        // Only the success path clears it when the server says invalid.
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback((token: string, uid: string, name: string) => {
    // Update React state synchronously, persist to storage async (fire-and-forget)
    setSessionToken(token);
    setCachedProfile({ userId: uid, displayName: name });
    setToken(token);
    setAuthenticated(true);
    setUserId(uid);
    setDisplayName(name);
    setLoading(false);
  }, []);

  const logout = useCallback(async () => {
    const token = await getSessionToken();
    if (token) {
      try {
        await apiLogout(token);
      } catch {
        /* best-effort */
      }
    }
    await clearSessionToken();
    setToken(null);
    setAuthenticated(false);
    setUserId(null);
    setDisplayName(null);
  }, []);

  const updateDisplayName = useCallback(
    (name: string) => {
      setDisplayName(name);
      if (userId) {
        setCachedProfile({ userId, displayName: name });
      }
    },
    [userId],
  );

  return (
    <AuthContext.Provider
      value={{
        loading,
        authenticated,
        userId,
        displayName,
        sessionToken,
        login,
        logout,
        setDisplayName: updateDisplayName,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  return useContext(AuthContext);
}
