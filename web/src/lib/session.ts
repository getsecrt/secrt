import { isTauri } from './config';

const SESSION_KEY = 'session_token';
const PROFILE_KEY = 'session_profile';

export interface CachedProfile {
  userId: string;
  displayName: string;
}

export async function getSessionToken(): Promise<string | null> {
  if (isTauri()) {
    const { keyringGet } = await import('./keyring');
    return keyringGet(SESSION_KEY);
  }
  try {
    return localStorage.getItem(SESSION_KEY);
  } catch {
    return null;
  }
}

/** Synchronous fast path for browser-only (used in initial render). */
export function getSessionTokenSync(): string | null {
  if (isTauri()) return null; // Tauri must use async path
  try {
    return localStorage.getItem(SESSION_KEY);
  } catch {
    return null;
  }
}

export async function setSessionToken(token: string): Promise<void> {
  if (isTauri()) {
    const { keyringSet } = await import('./keyring');
    await keyringSet(SESSION_KEY, token);
    return;
  }
  try {
    localStorage.setItem(SESSION_KEY, token);
  } catch {
    /* storage full or blocked */
  }
}

export async function getCachedProfile(): Promise<CachedProfile | null> {
  if (isTauri()) {
    const { keyringGet } = await import('./keyring');
    const raw = await keyringGet(PROFILE_KEY);
    if (!raw) return null;
    try {
      return JSON.parse(raw) as CachedProfile;
    } catch {
      return null;
    }
  }
  try {
    const raw = localStorage.getItem(PROFILE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as CachedProfile;
  } catch {
    return null;
  }
}

/** Synchronous fast path for browser-only (used in initial render). */
export function getCachedProfileSync(): CachedProfile | null {
  if (isTauri()) return null; // Tauri must use async path
  try {
    const raw = localStorage.getItem(PROFILE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as CachedProfile;
  } catch {
    return null;
  }
}

export async function setCachedProfile(profile: CachedProfile): Promise<void> {
  if (isTauri()) {
    const { keyringSet } = await import('./keyring');
    await keyringSet(PROFILE_KEY, JSON.stringify(profile));
    return;
  }
  try {
    localStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
  } catch {
    /* storage full or blocked */
  }
}

export async function clearSessionToken(): Promise<void> {
  if (isTauri()) {
    const { keyringDelete } = await import('./keyring');
    await Promise.all([keyringDelete(SESSION_KEY), keyringDelete(PROFILE_KEY)]);
    return;
  }
  try {
    localStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(PROFILE_KEY);
  } catch {
    /* blocked */
  }
}
