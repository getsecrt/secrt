import { createContext } from 'preact';
import { useState, useEffect, useCallback, useContext } from 'preact/hooks';
import type { ComponentChildren } from 'preact';
import { getSessionToken, setSessionToken, clearSessionToken } from './session';
import { fetchSession, logout as apiLogout } from './api';

export interface AuthState {
  loading: boolean;
  authenticated: boolean;
  userId: number | null;
  handle: string | null;
  sessionToken: string | null;
  login: (token: string, userId: number, handle: string) => void;
  logout: () => Promise<void>;
}

const defaultState: AuthState = {
  loading: true,
  authenticated: false,
  userId: null,
  handle: null,
  sessionToken: null,
  login: () => {},
  logout: async () => {},
};

const AuthContext = createContext<AuthState>(defaultState);

export function AuthProvider({ children }: { children: ComponentChildren }) {
  const [loading, setLoading] = useState(true);
  const [authenticated, setAuthenticated] = useState(false);
  const [userId, setUserId] = useState<number | null>(null);
  const [handle, setHandle] = useState<string | null>(null);
  const [sessionToken, setToken] = useState<string | null>(null);

  // On mount, try to restore session from localStorage
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
        if (res.authenticated) {
          setToken(token);
          setAuthenticated(true);
          setUserId(res.user_id);
          setHandle(res.handle);
        } else {
          clearSessionToken();
        }
      })
      .catch(() => {
        if (!cancelled) clearSessionToken();
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback((token: string, uid: number, h: string) => {
    setSessionToken(token);
    setToken(token);
    setAuthenticated(true);
    setUserId(uid);
    setHandle(h);
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
    setHandle(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{ loading, authenticated, userId, handle, sessionToken, login, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  return useContext(AuthContext);
}
