/**
 * Persistence for the Account Master Key (AMK).
 *
 * - **Tauri:** stored in OS keychain via `keyring` crate (base64url-encoded).
 * - **Browser:** stored in IndexedDB keyed by user ID.
 */

import { isTauri } from './config';
import { base64urlEncode, base64urlDecode } from '../crypto/encoding';

// --- Tauri keychain path ---

async function storeTauri(userId: string, amk: Uint8Array): Promise<void> {
  const { keyringSet } = await import('./keyring');
  await keyringSet(`amk:${userId}`, base64urlEncode(amk));
}

async function loadTauri(userId: string): Promise<Uint8Array | null> {
  const { keyringGet } = await import('./keyring');
  const raw = await keyringGet(`amk:${userId}`);
  if (!raw) return null;
  return base64urlDecode(raw);
}

async function clearTauri(userId: string): Promise<void> {
  const { keyringDelete } = await import('./keyring');
  await keyringDelete(`amk:${userId}`);
}

// --- Browser IndexedDB path ---

const DB_NAME = 'secrt-amk';
const DB_VERSION = 1;
const STORE_NAME = 'amk';

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function txPromise<T>(tx: IDBTransaction, request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve(request.result);
    tx.onerror = () => reject(tx.error);
  });
}

async function storeIdb(userId: string, amk: Uint8Array): Promise<void> {
  const db = await openDb();
  try {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    const req = store.put(amk, userId);
    await txPromise(tx, req);
  } finally {
    db.close();
  }
}

async function loadIdb(userId: string): Promise<Uint8Array | null> {
  const db = await openDb();
  try {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const req = store.get(userId);
    const result = await txPromise(tx, req);
    if (!result) return null;
    if (result instanceof Uint8Array) return result;
    if (result instanceof ArrayBuffer) return new Uint8Array(result);
    return null;
  } finally {
    db.close();
  }
}

async function clearIdb(userId: string): Promise<void> {
  const db = await openDb();
  try {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    const req = store.delete(userId);
    await txPromise(tx, req);
  } finally {
    db.close();
  }
}

// --- Public API ---

/** Store an AMK for a given user. */
export async function storeAmk(
  userId: string,
  amk: Uint8Array,
): Promise<void> {
  return isTauri() ? storeTauri(userId, amk) : storeIdb(userId, amk);
}

/** Load an AMK for a given user, or null if not found. */
export async function loadAmk(userId: string): Promise<Uint8Array | null> {
  return isTauri() ? loadTauri(userId) : loadIdb(userId);
}

/** Clear a stored AMK for a given user. */
export async function clearAmk(userId: string): Promise<void> {
  return isTauri() ? clearTauri(userId) : clearIdb(userId);
}
