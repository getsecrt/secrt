/**
 * IndexedDB persistence for the Account Master Key (AMK).
 *
 * The AMK is stored encrypted-at-rest in the browser's IndexedDB, keyed by
 * user ID. This module provides simple get/set/clear helpers.
 */

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

/** Store an AMK for a given user. */
export async function storeAmk(
  userId: string,
  amk: Uint8Array,
): Promise<void> {
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

/** Load an AMK for a given user, or null if not found. */
export async function loadAmk(userId: string): Promise<Uint8Array | null> {
  const db = await openDb();
  try {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const req = store.get(userId);
    const result = await txPromise(tx, req);
    if (!result) return null;
    // Ensure we return a Uint8Array (IDB may store as ArrayBuffer)
    if (result instanceof Uint8Array) return result;
    if (result instanceof ArrayBuffer) return new Uint8Array(result);
    return null;
  } finally {
    db.close();
  }
}

/** Clear a stored AMK for a given user. */
export async function clearAmk(userId: string): Promise<void> {
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
