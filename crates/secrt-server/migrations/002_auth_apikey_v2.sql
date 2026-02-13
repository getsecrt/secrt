-- Auth/session/passkey foundation and api key v2 storage model.

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

CREATE TABLE IF NOT EXISTS api_key_registrations (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'api_keys' AND column_name = 'key_hash'
    ) THEN
        ALTER TABLE api_keys RENAME COLUMN key_hash TO auth_hash;
    END IF;
END $$;

ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS auth_hash TEXT;

ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS user_id BIGINT REFERENCES users(id) ON DELETE SET NULL;

UPDATE api_keys SET auth_hash = '' WHERE auth_hash IS NULL;

ALTER TABLE api_keys
    ALTER COLUMN auth_hash SET NOT NULL;

ALTER TABLE secrets
    ADD COLUMN IF NOT EXISTS meta_key_version SMALLINT;

ALTER TABLE secrets
    ADD COLUMN IF NOT EXISTS enc_meta JSONB;

CREATE INDEX IF NOT EXISTS passkeys_user_id_idx ON passkeys (user_id, revoked_at);
CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id, expires_at);
CREATE INDEX IF NOT EXISTS webauthn_challenges_purpose_idx ON webauthn_challenges (purpose, expires_at);
CREATE INDEX IF NOT EXISTS apikey_regs_user_created_idx ON api_key_registrations (user_id, created_at);
CREATE INDEX IF NOT EXISTS apikey_regs_ip_created_idx ON api_key_registrations (ip_hash, created_at);

