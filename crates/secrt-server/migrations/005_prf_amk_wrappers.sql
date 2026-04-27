-- PRF-based AMK wrap path (Transport D).
-- Adds per-credential salt and PRF-capability flags to passkeys, and creates
-- prf_amk_wrappers — wrapped AMK blobs keyed by (user_id, credential).
-- See spec/v1/api.md §"Transport D: PRF wrap" and
-- crates/secrt-server/docs/prf-amk-wrapping.md.

-- ── passkeys: PRF capability columns ──────────────────────────────────
ALTER TABLE passkeys
    ADD COLUMN IF NOT EXISTS cred_salt      BYTEA,
    ADD COLUMN IF NOT EXISTS prf_supported  BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS prf_at_create  BOOLEAN NOT NULL DEFAULT false;

-- cred_salt is NULL for non-PRF credentials, exactly 32 bytes otherwise.
-- prf_supported: authenticator returned non-empty PRF output at some point.
-- prf_at_create: PRF output was available during the registration ceremony
--                (Chrome 147+/Hello, Safari 18+, etc.) vs. only on first
--                subsequent auth (older surfaces).
ALTER TABLE passkeys DROP CONSTRAINT IF EXISTS passkeys_cred_salt_len_chk;
ALTER TABLE passkeys
    ADD CONSTRAINT passkeys_cred_salt_len_chk
    CHECK (cred_salt IS NULL OR octet_length(cred_salt) = 32);

-- ── prf_amk_wrappers: per-credential wrapped AMK ──────────────────────
CREATE TABLE IF NOT EXISTS prf_amk_wrappers (
    id            BIGSERIAL PRIMARY KEY,
    user_id       UUID   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_pk BIGINT NOT NULL REFERENCES passkeys(id) ON DELETE CASCADE,
    wrapped_amk   BYTEA  NOT NULL,        -- 48 bytes (32 AMK + 16 GCM tag)
    nonce         BYTEA  NOT NULL,        -- 12 bytes
    version       SMALLINT NOT NULL DEFAULT 1,
    amk_commit    BYTEA  NOT NULL,        -- 32 bytes; matches amk_accounts.amk_commit
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, credential_pk),
    FOREIGN KEY (user_id) REFERENCES amk_accounts(user_id) ON DELETE CASCADE,
    CONSTRAINT prf_wrap_ct_len_chk     CHECK (octet_length(wrapped_amk) = 48),
    CONSTRAINT prf_wrap_nonce_len_chk  CHECK (octet_length(nonce) = 12),
    CONSTRAINT prf_wrap_commit_len_chk CHECK (octet_length(amk_commit) = 32),
    CONSTRAINT prf_wrap_version_chk    CHECK (version = 1)
);

CREATE INDEX IF NOT EXISTS prf_amk_wrappers_user_id_idx
    ON prf_amk_wrappers (user_id);
