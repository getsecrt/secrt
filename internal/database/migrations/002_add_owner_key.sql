ALTER TABLE secrets ADD COLUMN IF NOT EXISTS owner_key TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS secrets_owner_key_idx ON secrets (owner_key, expires_at);
