const SESSION_KEY = 'session_token';
const PROFILE_KEY = 'session_profile';

export interface CachedProfile {
  userId: string;
  displayName: string;
}

export function getSessionToken(): string | null {
  try {
    return localStorage.getItem(SESSION_KEY);
  } catch {
    return null;
  }
}

export function setSessionToken(token: string): void {
  try {
    localStorage.setItem(SESSION_KEY, token);
  } catch {
    /* storage full or blocked */
  }
}

export function getCachedProfile(): CachedProfile | null {
  try {
    const raw = localStorage.getItem(PROFILE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as CachedProfile;
  } catch {
    return null;
  }
}

export function setCachedProfile(profile: CachedProfile): void {
  try {
    localStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
  } catch {
    /* storage full or blocked */
  }
}

export function clearSessionToken(): void {
  try {
    localStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(PROFILE_KEY);
  } catch {
    /* blocked */
  }
}
