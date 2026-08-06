-- Separate Tailscale identity columns + confirm claim + auth rate limits
ALTER TABLE devices ADD COLUMN tailscale_stable_id TEXT;
ALTER TABLE devices ADD COLUMN tailscale_api_node_id TEXT;
ALTER TABLE devices ADD COLUMN claim_token TEXT;
ALTER TABLE devices ADD COLUMN claim_expires_at INTEGER;

-- Management id (API /device/{id}) and stable status Self.ID must each be unique when set
CREATE UNIQUE INDEX devices_tailscale_node_id_unique
  ON devices(tailscale_node_id) WHERE tailscale_node_id IS NOT NULL;
CREATE UNIQUE INDEX devices_tailscale_stable_id_unique
  ON devices(tailscale_stable_id) WHERE tailscale_stable_id IS NOT NULL;

CREATE TABLE rate_limits (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);
