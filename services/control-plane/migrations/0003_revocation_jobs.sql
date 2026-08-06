CREATE TABLE revocation_jobs (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  tailscale_node_id TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  completed_at INTEGER,
  last_error TEXT
);
CREATE INDEX revocation_jobs_pending ON revocation_jobs(completed_at, created_at);
