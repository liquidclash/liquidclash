-- Durable confirm ownership generations and bounded auth limiter maintenance.
ALTER TABLE devices ADD COLUMN claim_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN tailscale_public_key TEXT;

-- StableNodeID comes from the local status document and is audit metadata.
-- The server-authoritative Device API management id remains the ownership key.
DROP INDEX devices_tailscale_stable_id_unique;

ALTER TABLE revocation_jobs ADD COLUMN ownership_generation INTEGER NOT NULL DEFAULT -1;
ALTER TABLE revocation_jobs ADD COLUMN reason TEXT NOT NULL DEFAULT 'revocation';

CREATE INDEX rate_limits_window_start ON rate_limits(window_start);
