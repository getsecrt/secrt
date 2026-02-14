import { base64urlEncode, base64urlDecode } from '../crypto/encoding';

/** Check if the browser supports WebAuthn. */
export function supportsWebAuthn(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined'
  );
}

export interface CreatePasskeyResult {
  credentialId: string;
  publicKey: string;
}

/** Call navigator.credentials.create() with discoverable credential settings. */
export async function createPasskeyCredential(
  challenge: string,
  userId: string,
  userName: string,
  displayName: string,
): Promise<CreatePasskeyResult> {
  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge: base64urlDecode(challenge),
      rp: { name: 'secrt', id: window.location.hostname },
      user: {
        id: base64urlDecode(userId),
        name: userName,
        displayName,
      },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },   // ES256
        { alg: -257, type: 'public-key' },  // RS256
      ],
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'preferred',
      },
      timeout: 60000,
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error('Credential creation returned null');

  const response = credential.response as AuthenticatorAttestationResponse;
  const publicKeyBytes = response.getPublicKey?.();
  if (!publicKeyBytes) throw new Error('No public key in attestation response');

  return {
    credentialId: base64urlEncode(new Uint8Array(credential.rawId)),
    publicKey: base64urlEncode(new Uint8Array(publicKeyBytes)),
  };
}

export interface GetPasskeyResult {
  credentialId: string;
}

/** Call navigator.credentials.get() for discoverable credentials (no allowCredentials). */
export async function getPasskeyCredential(
  challenge: string,
): Promise<GetPasskeyResult> {
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: base64urlDecode(challenge),
      rpId: window.location.hostname,
      userVerification: 'preferred',
      timeout: 60000,
    },
  })) as PublicKeyCredential | null;

  if (!credential) throw new Error('Credential assertion returned null');

  return {
    credentialId: base64urlEncode(new Uint8Array(credential.rawId)),
  };
}

/** Generate a random user ID for WebAuthn ceremonies (16 bytes, base64url). */
export function generateUserId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64urlEncode(bytes);
}
