PRAGMA foreign_keys = ON;

CREATE TABLE users (
  id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL, password_salt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
  quota_bytes INTEGER, usage_bytes INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE invitations (
  id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, email TEXT NOT NULL COLLATE NOCASE,
  expires_at INTEGER NOT NULL, redeemed_at INTEGER, created_at INTEGER NOT NULL
);
CREATE TABLE devices (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  installation_id TEXT NOT NULL, name TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','active','revoked')),
  pending_expires_at INTEGER, tailscale_node_id TEXT, tailscale_ips TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  UNIQUE(user_id, installation_id)
);
CREATE TRIGGER devices_max_two_insert BEFORE INSERT ON devices
WHEN NEW.status IN ('pending','active') AND
 (SELECT COUNT(*) FROM devices WHERE user_id=NEW.user_id AND status IN ('pending','active')) >= 2
BEGIN SELECT RAISE(ABORT, 'DEVICE_LIMIT'); END;
CREATE TRIGGER devices_max_two_update BEFORE UPDATE OF status ON devices
WHEN NEW.status IN ('pending','active') AND OLD.status NOT IN ('pending','active') AND
 (SELECT COUNT(*) FROM devices WHERE user_id=NEW.user_id AND status IN ('pending','active')) >= 2
BEGIN SELECT RAISE(ABORT, 'DEVICE_LIMIT'); END;
CREATE TABLE sessions (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  refresh_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL, revoked_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE TABLE usage_reports (
  report_id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  total_bytes INTEGER NOT NULL CHECK(total_bytes >= 0), observed_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX devices_user_status ON devices(user_id,status);
CREATE INDEX sessions_hash ON sessions(refresh_hash);
