-- Track coarse (month-start) last-activity date for stale-account cleanup.
-- Uses DATE (not TIMESTAMPTZ) so sub-day precision is structurally impossible,
-- preserving privacy in a zero-knowledge system.
ALTER TABLE users ADD COLUMN last_active_at DATE NOT NULL DEFAULT date_trunc('month', now())::date;

-- Backfill existing rows with their registration month.
UPDATE users SET last_active_at = date_trunc('month', created_at)::date;
