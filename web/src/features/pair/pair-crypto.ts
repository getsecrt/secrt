/**
 * ECDH-based AMK transfer helpers for the web-pair flow. Mirrors the
 * encrypt/decrypt blocks already inlined in DevicePage.tsx and
 * AppLoginPage.tsx, hoisted here so the display + join panels can share
 * one implementation.
 *
 * AAD is the literal string `secrt-amk-transfer-v1` — the same domain tag
 * used by every other AMK-transfer transport in the codebase.
 */

import {
  generateEcdhKeyPair,
  exportPublicKey,
  performEcdh,
  deriveTransferKey,
  computeAmkCommit,
} from '../../crypto/amk';
import { base64urlEncode, base64urlDecode } from '../../crypto/encoding';
import { commitAmk, type PairAmkTransfer } from '../../lib/api';
import { storeAmk } from '../../lib/amk-store';

const AAD_STRING = 'secrt-amk-transfer-v1';

const buf = (a: Uint8Array): ArrayBuffer => {
  const b = new ArrayBuffer(a.byteLength);
  new Uint8Array(b).set(a);
  return b;
};

/**
 * Encrypt `amk` to a peer ECDH pubkey. Generates an ephemeral keypair and
 * returns `{ amk_transfer, browserPkBytes }` — the transfer can be sent to
 * either `pairApprove` or attached to a `device-auth` approval.
 */
export async function encryptAmkForPeer(
  peerPubKeyB64: string,
  amk: Uint8Array,
): Promise<{ amkTransfer: PairAmkTransfer; browserPkBytes: Uint8Array }> {
  const browserKp = await generateEcdhKeyPair();
  const browserPkBytes = await exportPublicKey(browserKp.publicKey);
  const peerPkBytes = base64urlDecode(peerPubKeyB64);
  const sharedSecret = await performEcdh(browserKp.privateKey, peerPkBytes);
  const transferKey = await deriveTransferKey(sharedSecret);

  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);
  const aad = new TextEncoder().encode(AAD_STRING);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    buf(transferKey),
    'AES-GCM',
    false,
    ['encrypt'],
  );
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: buf(nonce), additionalData: buf(aad) },
    cryptoKey,
    buf(amk),
  );

  return {
    amkTransfer: {
      ct: base64urlEncode(new Uint8Array(ct)),
      nonce: base64urlEncode(nonce),
      ecdh_public_key: base64urlEncode(browserPkBytes),
    },
    browserPkBytes,
  };
}

/**
 * Decrypt the AMK from a peer's transfer using our private key. Throws if
 * the GCM tag fails to verify (which the receiver must surface as a
 * possible-tamper error rather than fall through silently).
 */
/**
 * The class of error returned when the receiver-side AMK commit lookup
 * comes back `409`. A separate type lets the UI render specific
 * cross-account copy without string-matching error messages.
 */
export class AmkCommitMismatchError extends Error {
  constructor() {
    super('amk_commit_mismatch');
    this.name = 'AmkCommitMismatchError';
  }
}

/**
 * The receiver-side commit-then-store sequence. Verifies the commit
 * against the server (so a different-account AMK is never written to
 * local storage), then stores on success. Throws
 * `AmkCommitMismatchError` on `409` so the UI can render specific copy.
 *
 * The order — commit *before* store — is a security invariant. Tests in
 * `pair-crypto.test.ts` pin the order against regression.
 */
export async function verifyAndStoreReceivedAmk(args: {
  sessionToken: string;
  userId: string;
  amk: Uint8Array;
  signal?: AbortSignal;
}): Promise<void> {
  const commit = await computeAmkCommit(args.amk);
  try {
    await commitAmk(args.sessionToken, base64urlEncode(commit), args.signal);
  } catch (err) {
    const msg = err instanceof Error ? err.message : '';
    if (msg.includes('409') || /mismatch/i.test(msg)) {
      throw new AmkCommitMismatchError();
    }
    throw err;
  }
  await storeAmk(args.userId, args.amk);
}

export async function decryptAmkFromPeer(
  ourPrivateKey: CryptoKey,
  transfer: PairAmkTransfer,
): Promise<Uint8Array> {
  const peerPkBytes = base64urlDecode(transfer.ecdh_public_key);
  const sharedSecret = await performEcdh(ourPrivateKey, peerPkBytes);
  const transferKey = await deriveTransferKey(sharedSecret);

  const ct = base64urlDecode(transfer.ct);
  const nonce = base64urlDecode(transfer.nonce);
  const aad = new TextEncoder().encode(AAD_STRING);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    buf(transferKey),
    'AES-GCM',
    false,
    ['decrypt'],
  );
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: buf(nonce), additionalData: buf(aad) },
    cryptoKey,
    buf(ct),
  );
  return new Uint8Array(pt);
}
