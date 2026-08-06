-- User-initiated diagnostics uploads. The kill switch may have the machine
-- fully network-blocked when the client fails, but the firewall policy permits
-- this API host on TCP/443, so this table is the recovery-channel drop box for
-- a support conversation. It is a short-lived diagnostic artifact, not a
-- permanent record: the scheduled cleanup deletes rows past retention and
-- deleting a user removes their reports.
PRAGMA foreign_keys = ON;

CREATE TABLE diagnostics_reports (
  id TEXT PRIMARY KEY,
  -- Read aloud to support, so the alphabet excludes 0/O/1/I.
  -- A repeated character class per position exceeds the engine's GLOB
  -- complexity limit, so bound the length and exclude the alphabet's
  -- complement instead.
  reference_code TEXT NOT NULL UNIQUE
    CHECK(length(reference_code) = 8
      AND reference_code NOT GLOB '*[^2-9A-HJ-NP-Z]*'),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  received_at INTEGER NOT NULL,
  -- Denormalised out of report_json (`appVersion` / `osVersion`): the client
  -- sends them only inside the report, and triage sorts by them often enough
  -- to want columns rather than JSON extraction. Bounds match the Worker's.
  client_version TEXT NOT NULL CHECK(length(client_version) BETWEEN 1 AND 40),
  os_version TEXT NOT NULL CHECK(length(os_version) BETWEEN 1 AND 80),
  -- Canonicalised, whitelisted structured report, in the client's own key
  -- order. The Worker rejects anything larger rather than truncating; this
  -- bound is the storage backstop.
  report_json TEXT NOT NULL CHECK(length(report_json) <= 16384)
);

-- Support looks a report up by the code the user reads over the phone (already
-- covered by the UNIQUE index). These serve per-account triage and retention.
CREATE INDEX diagnostics_reports_user_recent
  ON diagnostics_reports(user_id, received_at DESC);
CREATE INDEX diagnostics_reports_retention
  ON diagnostics_reports(received_at);

-- Same posture as 0006: an accepted report is immutable evidence. There is no
-- client-supplied idempotency key here, so instead of resolving a replay the
-- trigger refuses mutation outright. Retention deletes; nothing rewrites.
CREATE TRIGGER diagnostics_reports_immutable_update
BEFORE UPDATE ON diagnostics_reports
BEGIN
  SELECT RAISE(ABORT, 'DIAGNOSTICS_REPORT_IMMUTABLE');
END;
