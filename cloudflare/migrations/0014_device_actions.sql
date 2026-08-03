PRAGMA foreign_keys = ON;

CREATE TABLE device_actions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  action TEXT NOT NULL CHECK(action IN ('diagnostic_snapshot','claude_traffic_snapshot','refresh_catalog','retry_protection')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','delivered','succeeded','failed','expired')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  delivered_at INTEGER,
  completed_at INTEGER,
  result_json TEXT CHECK(result_json IS NULL OR length(result_json) <= 2048)
);
CREATE INDEX device_actions_device_pending ON device_actions(device_id,status,expires_at);
CREATE INDEX device_actions_recent ON device_actions(created_at DESC);
CREATE INDEX device_actions_user ON device_actions(user_id,created_at DESC);
