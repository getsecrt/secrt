-- Atomic AMK commitment anchor: one AMK per user, first writer wins
CREATE TABLE IF NOT EXISTS amk_accounts (
    user_id   UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    amk_commit BYTEA NOT NULL,         -- SHA-256("secrt-amk-commit-v1" || AMK), 32 bytes
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-API-key wrapped AMK blobs
CREATE TABLE IF NOT EXISTS amk_wrappers (
    id        BIGSERIAL PRIMARY KEY,
    user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_prefix TEXT NOT NULL,
    wrapped_amk BYTEA NOT NULL,        -- AES-256-GCM ciphertext + tag (48 bytes)
    nonce     BYTEA NOT NULL,          -- 12 bytes
    version   SMALLINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, key_prefix),
    FOREIGN KEY (user_id) REFERENCES amk_accounts(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS amk_wrappers_user_id_idx ON amk_wrappers (user_id);
