-- Keep the product default at two devices while allowing explicit per-user
-- test allowances without weakening every account.
ALTER TABLE users
ADD COLUMN device_limit INTEGER NOT NULL DEFAULT 2
CHECK(device_limit BETWEEN 1 AND 25);

DROP TRIGGER devices_max_two_insert;
DROP TRIGGER devices_max_two_update;

CREATE TRIGGER devices_user_limit_insert BEFORE INSERT ON devices
WHEN NEW.status IN ('pending','active') AND
 (SELECT COUNT(*) FROM devices
  WHERE user_id = NEW.user_id AND status IN ('pending','active')) >=
 (SELECT device_limit FROM users WHERE id = NEW.user_id)
BEGIN SELECT RAISE(ABORT, 'DEVICE_LIMIT'); END;

CREATE TRIGGER devices_user_limit_update BEFORE UPDATE OF status ON devices
WHEN NEW.status IN ('pending','active') AND OLD.status NOT IN ('pending','active') AND
 (SELECT COUNT(*) FROM devices
  WHERE user_id = NEW.user_id AND status IN ('pending','active')) >=
 (SELECT device_limit FROM users WHERE id = NEW.user_id)
BEGIN SELECT RAISE(ABORT, 'DEVICE_LIMIT'); END;
