-- Initial schema (v0.6.0)

-- Secrets (ciphertext envelopes only)
CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    claim_hash TEXT NOT NULL,
    envelope JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    owner_key TEXT NOT NULL DEFAULT '',
    meta_key_version SMALLINT,
    enc_meta JSONB
);

CREATE INDEX IF NOT EXISTS secrets_expires_at_idx ON secrets (expires_at);
CREATE INDEX IF NOT EXISTS secrets_owner_key_idx ON secrets (owner_key, expires_at);

-- User/passkey/session auth foundation
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    handle TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS passkeys (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS sessions (
    id BIGSERIAL PRIMARY KEY,
    sid TEXT NOT NULL UNIQUE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id BIGSERIAL PRIMARY KEY,
    challenge_id TEXT NOT NULL UNIQUE,
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL,
    challenge_json TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- API keys (v2 auth-hash model)
CREATE TABLE IF NOT EXISTS api_keys (
    id BIGSERIAL PRIMARY KEY,
    key_prefix TEXT NOT NULL UNIQUE,
    auth_hash TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '',
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

-- Registration accounting for account/IP quotas
CREATE TABLE IF NOT EXISTS api_key_registrations (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS passkeys_user_id_idx ON passkeys (user_id, revoked_at);
CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id, expires_at);
CREATE INDEX IF NOT EXISTS webauthn_challenges_purpose_idx ON webauthn_challenges (purpose, expires_at);
CREATE INDEX IF NOT EXISTS apikey_regs_user_created_idx ON api_key_registrations (user_id, created_at);
CREATE INDEX IF NOT EXISTS apikey_regs_ip_created_idx ON api_key_registrations (ip_hash, created_at);
