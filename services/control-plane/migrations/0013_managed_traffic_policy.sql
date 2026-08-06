-- One encrypted, revisioned direct-routing policy shared by authenticated Tono users.
-- No seed row: migrations cannot access the Worker AES-GCM secret, so plaintext is never stored.
CREATE TABLE managed_traffic_policy (
  singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
  revision INTEGER NOT NULL CHECK(revision > 0),
  ciphertext TEXT NOT NULL,
  nonce TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
