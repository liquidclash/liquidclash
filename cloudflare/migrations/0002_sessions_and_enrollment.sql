ALTER TABLE users ADD COLUMN name TEXT;
ALTER TABLE users ADD COLUMN plan TEXT;
ALTER TABLE users ADD COLUMN expires_at INTEGER;

ALTER TABLE devices ADD COLUMN last_seen_at INTEGER;
ALTER TABLE devices ADD COLUMN confirmed_at INTEGER;
ALTER TABLE devices ADD COLUMN enrollment_issued_at INTEGER;

ALTER TABLE sessions ADD COLUMN device_id TEXT REFERENCES devices(id) ON DELETE CASCADE;
CREATE INDEX sessions_device ON sessions(device_id, revoked_at);
