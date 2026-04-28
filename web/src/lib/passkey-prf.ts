import {
  deriveAmkWrapKeyFromPrf,
  buildWrapAadPrf,
  wrapAmk,
} from '../crypto/amk';
import { base64urlEncode, base64urlDecode } from '../crypto/encoding';
import { getPasskeyCredential } from './webauthn';
import { putPrfWrapper } from './api';

/**
 * Derive the PRF wrap key, wrap the AMK, and PUT the resulting blob to
 * `/api/v1/auth/passkeys/{credential_id}/prf-wrapper`.
 *
 * Used by three callers that all share the same wrap shape:
 *   1. RegisterPage — wraps right after a freshly created passkey.
 *   2. SettingsPage add-passkey — wraps right after adding a passkey.
 *   3. LoginPage upgrade path — wraps right after a successful login on a
 *      pre-PRF credential whose row was just retrofitted with a `cred_salt`.
 *
 * `prfOutput` is the PRF output already in hand. When absent, falls back
 * to a fresh get() ceremony pinned to `credentialId` via allowCredentials —
 * needed when the authenticator only returns PRF on assertion, not on
 * create. The fallback rejects credential mismatch (would otherwise
 * silently produce an undecryptable wrapper).
 */
export async function wrapAndStorePrfWrapper(
  sessionToken: string,
  userId: string,
  credentialId: string,
  credentialRawId: Uint8Array,
  credSaltB64u: string,
  prfOutput: Uint8Array | undefined,
  amk: Uint8Array,
  amkCommit: Uint8Array,
): Promise<void> {
  let output = prfOutput;
  if (!output) {
    const localChallenge = new Uint8Array(32);
    crypto.getRandomValues(localChallenge);
    const assertion = await getPasskeyCredential(
      base64urlEncode(localChallenge),
      {
        enablePrf: true,
        allowCredentialIds: [credentialId],
      },
    );
    if (assertion.credentialId !== credentialId) {
      throw new Error(
        'PRF fallback returned a different credential — refusing to write a mismatched wrapper',
      );
    }
    if (!assertion.prfOutput) {
      throw new Error('PRF fallback assertion returned no output');
    }
    output = assertion.prfOutput;
  }

  const credSalt = base64urlDecode(credSaltB64u);
  const wrapKey = await deriveAmkWrapKeyFromPrf(output, credSalt);
  const aad = buildWrapAadPrf(userId, credentialRawId, 1);
  const wrapped = await wrapAmk(amk, wrapKey, aad);

  await putPrfWrapper(sessionToken, credentialId, {
    wrapped_amk: wrapped.ct,
    nonce: wrapped.nonce,
    amk_commit: base64urlEncode(amkCommit),
    version: 1,
  });
}
