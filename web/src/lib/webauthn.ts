import { base64urlEncode, base64urlDecode } from '../crypto/encoding';
import { debugInfo } from './debug-log';

/** Check if the browser supports WebAuthn. */
export function supportsWebAuthn(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined'
  );
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}

/**
 * Per-RP PRF eval salt. Stable for the lifetime of the RP — synced passkey
 * providers (Apple iCloud Keychain, Google Password Manager) produce
 * deterministic PRF outputs only when the same eval salt is supplied across
 * the synced device set. See spec/v1/api.md §"Transport D: PRF wrap".
 *
 * Computed lazily on first use and cached.
 */
let prfEvalSaltCache: Uint8Array | null = null;
async function prfEvalSalt(): Promise<Uint8Array> {
  if (prfEvalSaltCache) return prfEvalSaltCache;
  const label = new TextEncoder().encode('secrt.is/v1/amk-prf-eval-salt');
  const digest = await crypto.subtle.digest('SHA-256', toArrayBuffer(label));
  prfEvalSaltCache = new Uint8Array(digest);
  return prfEvalSaltCache;
}

/** State observed about the authenticator's PRF support during a ceremony. */
export interface PrfRegisterState {
  /** Authenticator returned non-empty PRF output. */
  supported: boolean;
  /** PRF output was available at create time (PRF-on-create). */
  atCreate: boolean;
  /** The 32-byte PRF output if available at create time. */
  onCreateOutput?: Uint8Array;
}

export interface CreatePasskeyResult {
  credentialId: string;
  /**
   * base64url of the raw `authenticatorData` bytes parsed out of
   * `attestationObject`. Carries the attested credential data section
   * with the COSE_Key the server extracts and persists. See
   * spec/v1/server.md §6.2.
   */
  authenticatorData: string;
  /** base64url of the literal `clientDataJSON` bytes the browser produced. */
  clientDataJSON: string;
  rawId: Uint8Array;
  prfState: PrfRegisterState;
}

/**
 * Call navigator.credentials.create() with discoverable credential settings.
 *
 * When `enablePrf` is true, the WebAuthn PRF extension is requested and UV
 * is upgraded to "required" (PRF gates on UV on most platforms). The result
 * carries a `prfState` describing what the authenticator returned so the
 * caller can branch on PRF-on-create vs PRF-on-get-only vs unsupported.
 */
export async function createPasskeyCredential(
  challenge: string,
  userId: string,
  userName: string,
  displayName: string,
  opts: { enablePrf?: boolean } = {},
): Promise<CreatePasskeyResult> {
  const extensions: Record<string, unknown> = {};
  if (opts.enablePrf) {
    extensions.prf = {
      eval: { first: toArrayBuffer(await prfEvalSalt()) },
    };
  }

  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: toArrayBuffer(base64urlDecode(challenge)),
      rp: { name: 'secrt', id: window.location.hostname },
      user: {
        id: toArrayBuffer(base64urlDecode(userId)),
        name: userName,
        displayName,
      },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' }, // ES256
        { alg: -257, type: 'public-key' }, // RS256
      ],
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: opts.enablePrf ? 'required' : 'preferred',
      },
      ...(opts.enablePrf ? { extensions } : {}),
      timeout: 60000,
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error('Credential creation returned null');

  const response = credential.response as AuthenticatorAttestationResponse;
  // getAuthenticatorData() returns the raw authData bytes (parsed out of the
  // CBOR attestationObject by the browser). Modern browsers only — Chrome 85+,
  // Firefox 119+, Safari 17.4+. We don't support attestation, so the rest of
  // the attestationObject (fmt, attStmt) is intentionally discarded.
  const authData = response.getAuthenticatorData?.();
  if (!authData) {
    throw new Error(
      'Browser does not support response.getAuthenticatorData() — please upgrade',
    );
  }

  const ext =
    typeof credential.getClientExtensionResults === 'function'
      ? credential.getClientExtensionResults()
      : ({} as AuthenticationExtensionsClientOutputs);
  const prfExt = (
    ext as { prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } } }
  ).prf;
  let prfState: PrfRegisterState;
  if (!prfExt) {
    // Browser/authenticator dropped the extension entirely (e.g. Bitwarden,
    // 1Password as picker, Firefox ≤147, no-PRF surfaces).
    prfState = { supported: false, atCreate: false };
  } else if (prfExt.results?.first) {
    // PRF-on-create: ideal path. Output available immediately so we can wrap
    // the AMK in the same flow without a second ceremony.
    prfState = {
      supported: true,
      atCreate: true,
      onCreateOutput: new Uint8Array(prfExt.results.first),
    };
  } else if (prfExt.enabled === true) {
    // PRF-on-get-only: extension acknowledged but output deferred to a get()
    // ceremony. Caller should re-assert with allowCredentials = [credentialId].
    prfState = { supported: true, atCreate: false };
  } else {
    // prf.enabled === false explicitly: authenticator declined.
    prfState = { supported: false, atCreate: false };
  }

  const credentialId = base64urlEncode(new Uint8Array(credential.rawId));
  debugInfo('webauthn-create', {
    credIdPrefix: credentialId.slice(0, 8),
    authenticatorAttachment:
      (
        credential as PublicKeyCredential & {
          authenticatorAttachment?: string | null;
        }
      ).authenticatorAttachment ?? null,
    prfExtPresent: !!prfExt,
    prfEnabled: prfExt?.enabled,
    prfHasResults: !!prfExt?.results?.first,
    prfState: {
      supported: prfState.supported,
      atCreate: prfState.atCreate,
    },
  });
  return {
    credentialId,
    authenticatorData: base64urlEncode(new Uint8Array(authData)),
    clientDataJSON: base64urlEncode(new Uint8Array(response.clientDataJSON)),
    rawId: new Uint8Array(credential.rawId),
    prfState,
  };
}

export interface GetPasskeyResult {
  credentialId: string;
  /** base64url of `AuthenticatorAssertionResponse.authenticatorData`. */
  authenticatorData: string;
  /** base64url of the literal `clientDataJSON` bytes. */
  clientDataJSON: string;
  /**
   * base64url of the DER-encoded ECDSA signature (ES256) over
   * `authenticatorData || SHA-256(clientDataJSON)`. Server verifies against
   * the stored COSE_Key.
   */
  signature: string;
  rawId: Uint8Array;
  /**
   * 32-byte PRF output from the assertion when the PRF extension was
   * requested and the authenticator returned a value. Undefined otherwise.
   */
  prfOutput?: Uint8Array;
}

export interface GetPasskeyOptions {
  /** When true, request PRF on the assertion and bump UV to "required". */
  enablePrf?: boolean;
  /**
   * Constrain the picker to a specific set of credential IDs. Used by the
   * PRF-on-get-only fallback so it can target the just-registered credential
   * rather than letting the user pick a different (possibly non-PRF) one.
   * Each entry MUST be a base64url credential_id.
   */
  allowCredentialIds?: string[];
}

/**
 * Call navigator.credentials.get(). Defaults to a discoverable assertion
 * (no allowCredentials). Pass `allowCredentialIds` to constrain the picker
 * and `enablePrf` to request a PRF output.
 */
export async function getPasskeyCredential(
  challenge: string,
  opts: GetPasskeyOptions = {},
): Promise<GetPasskeyResult> {
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: toArrayBuffer(base64urlDecode(challenge)),
    rpId: window.location.hostname,
    userVerification: opts.enablePrf ? 'required' : 'preferred',
    timeout: 60000,
  };

  if (opts.allowCredentialIds && opts.allowCredentialIds.length > 0) {
    publicKey.allowCredentials = opts.allowCredentialIds.map((id) => ({
      id: toArrayBuffer(base64urlDecode(id)),
      type: 'public-key' as const,
    }));
  }

  if (opts.enablePrf) {
    (publicKey as { extensions?: Record<string, unknown> }).extensions = {
      prf: { eval: { first: toArrayBuffer(await prfEvalSalt()) } },
    };
  }

  const credential = (await navigator.credentials.get({
    publicKey,
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error('Credential assertion returned null');

  const response = credential.response as AuthenticatorAssertionResponse;
  const ext =
    typeof credential.getClientExtensionResults === 'function'
      ? credential.getClientExtensionResults()
      : ({} as AuthenticationExtensionsClientOutputs);
  const prfExt = (ext as { prf?: { results?: { first?: ArrayBuffer } } }).prf;
  const prfOutput = prfExt?.results?.first
    ? new Uint8Array(prfExt.results.first)
    : undefined;

  const credentialId = base64urlEncode(new Uint8Array(credential.rawId));
  debugInfo('webauthn-get', {
    credIdPrefix: credentialId.slice(0, 8),
    authenticatorAttachment:
      (
        credential as PublicKeyCredential & {
          authenticatorAttachment?: string | null;
        }
      ).authenticatorAttachment ?? null,
    prfRequested: !!opts.enablePrf,
    prfExtPresent: !!prfExt,
    hasPrfOutput: !!prfOutput,
    constrained: !!(opts.allowCredentialIds && opts.allowCredentialIds.length),
  });
  return {
    credentialId,
    authenticatorData: base64urlEncode(
      new Uint8Array(response.authenticatorData),
    ),
    clientDataJSON: base64urlEncode(new Uint8Array(response.clientDataJSON)),
    signature: base64urlEncode(new Uint8Array(response.signature)),
    rawId: new Uint8Array(credential.rawId),
    prfOutput,
  };
}

/** Generate a random user ID for WebAuthn ceremonies (16 bytes, base64url). */
export function generateUserId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64urlEncode(bytes);
}
