-- A report id is an immutable idempotency key. Replaying the exact same
-- observation is allowed; reusing the id for different content is rejected.
CREATE TRIGGER usage_reports_immutable_insert
BEFORE INSERT ON usage_reports
WHEN EXISTS (
  SELECT 1
  FROM usage_reports
  WHERE report_id = NEW.report_id
    AND (
      user_id != NEW.user_id
      OR total_bytes != NEW.total_bytes
      OR observed_at != NEW.observed_at
    )
)
BEGIN
  SELECT RAISE(ABORT, 'USAGE_REPORT_CONFLICT');
END;
