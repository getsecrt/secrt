/** Metadata stored inside the encrypted payload frame. */
export interface PayloadMeta {
  type: 'text' | 'file' | 'binary';
  filename?: string;
  mime?: string;
  [key: string]: unknown;
}

/** Result of sealing plaintext into an envelope. */
export interface SealResult {
  envelope: EnvelopeJson;
  urlKey: Uint8Array;
  claimHash: string;
}

/** Result of opening (decrypting) an envelope. */
export interface OpenResult {
  content: Uint8Array;
  meta: PayloadMeta;
}

/** Envelope JSON structure matching the v1 spec. */
export interface EnvelopeJson {
  v: 1;
  suite: 'v1-pbkdf2-hkdf-aes256gcm-sealed-payload';
  enc: {
    alg: 'A256GCM';
    nonce: string;
    ciphertext: string;
  };
  kdf: KdfNone | KdfPbkdf2;
  hkdf: {
    hash: 'SHA-256';
    salt: string;
    enc_info: string;
    claim_info: string;
    length: 32;
  };
}

export interface KdfNone {
  name: 'none';
}

export interface KdfPbkdf2 {
  name: 'PBKDF2-SHA256';
  salt: string;
  iterations: number;
  length: 32;
}

/** Server API response types. */
export interface ApiInfoRate {
  requests_per_second: number;
  burst: number;
}

export interface ApiInfoTier {
  max_envelope_bytes: number;
  max_secrets: number;
  max_total_bytes: number;
  rate: ApiInfoRate;
}

export interface ApiInfo {
  authenticated: boolean;
  ttl: {
    default_seconds: number;
    max_seconds: number;
  };
  limits: {
    public: ApiInfoTier;
    authed: ApiInfoTier;
  };
  claim_rate: ApiInfoRate;
}

export interface CreateRequest {
  envelope: EnvelopeJson;
  claim_hash: string;
  ttl_seconds?: number;
}

export interface CreateResponse {
  id: string;
  expires_at: string;
}

export interface ClaimRequest {
  claim: string;
}

export interface ClaimResponse {
  envelope: EnvelopeJson;
}

/** Auth API types. */
export interface PasskeyRegisterStartRequest {
  display_name: string;
}

export interface ChallengeResponse {
  challenge_id: string;
  challenge: string;
  expires_at: string;
}

export interface PasskeyRegisterFinishRequest {
  challenge_id: string;
  credential_id: string;
  public_key: string;
}

export interface PasskeyLoginStartRequest {
  credential_id: string;
}

export interface PasskeyLoginFinishRequest {
  challenge_id: string;
  credential_id: string;
}

export interface AuthFinishResponse {
  session_token: string;
  display_name: string;
  expires_at: string;
}

export interface SessionResponse {
  authenticated: boolean;
  display_name: string | null;
  expires_at: string | null;
}

/** Dashboard API types. */
export interface SecretMetadata {
  id: string;
  share_url: string;
  expires_at: string;
  created_at: string;
  state: string;
  ciphertext_size: number;
  passphrase_protected: boolean;
}

export interface ListSecretsResponse {
  secrets: SecretMetadata[];
  total: number;
  limit: number;
  offset: number;
}

export interface ApiKeyItem {
  prefix: string;
  scopes: string;
  created_at: string;
  revoked_at: string | null;
}

export interface ListApiKeysResponse {
  api_keys: ApiKeyItem[];
}

export interface DeleteAccountResponse {
  ok: boolean;
  secrets_burned: number;
  keys_revoked: number;
}
