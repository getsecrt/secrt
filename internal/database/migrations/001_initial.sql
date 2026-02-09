-- Secrets (ciphertext envelopes only)
CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    claim_hash TEXT NOT NULL,
    envelope JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    owner_key TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS secrets_expires_at_idx ON secrets (expires_at);
CREATE INDEX IF NOT EXISTS secrets_owner_key_idx ON secrets (owner_key, expires_at);

-- API keys for automation
CREATE TABLE IF NOT EXISTS api_keys (
    id BIGSERIAL PRIMARY KEY,
    key_prefix TEXT NOT NULL UNIQUE,
    key_hash TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

