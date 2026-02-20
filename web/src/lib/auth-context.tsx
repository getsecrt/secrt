import { createContext } from 'preact';
import { useState, useEffect, useCallback, useContext } from 'preact/hooks';
import type { ComponentChildren } from 'preact';
import {
  getSessionToken,
  setSessionToken,
  clearSessionToken,
  getCachedProfile,
  setCachedProfile,
} from './session';
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
  // Read cached auth state synchronously to avoid a flash of wrong UI.
  // - No token → loading: false immediately (we know user is unauthenticated)
  // - Token + cached profile → loading: false, render authenticated UI instantly
  // - Token but no cache → loading: true, wait for fetchSession
  const [cached] = useState(() => {
    const token = getSessionToken();
    const profile = token ? getCachedProfile() : null;
    return { token, profile };
  });

  const [loading, setLoading] = useState(!!cached.token && !cached.profile);
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
    const token = getSessionToken();
    if (!token) {
      setLoading(false);
      return;
    }

    let cancelled = false;
    fetchSession(token)
      .then((res) => {
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
          clearSessionToken();
          setAuthenticated(false);
          setToken(null);
          setUserId(null);
          setDisplayName(null);
        }
      })
      .catch(() => {
        // Network error or aborted request — don't clear the token.
        // Only the .then() path clears it when the server says invalid.
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback((token: string, uid: string, name: string) => {
    setSessionToken(token);
    setCachedProfile({ userId: uid, displayName: name });
    setToken(token);
    setAuthenticated(true);
    setUserId(uid);
    setDisplayName(name);
    setLoading(false);
  }, []);

  const logout = useCallback(async () => {
    const token = getSessionToken();
    if (token) {
      try {
        await apiLogout(token);
      } catch {
        /* best-effort */
      }
    }
    clearSessionToken();
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
