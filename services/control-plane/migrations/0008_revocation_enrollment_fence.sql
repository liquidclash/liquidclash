-- Enrollment checks this device-scoped fence before issuing any replacement
-- auth key. Keep the outage path indexed as unfinished jobs accumulate.
CREATE INDEX revocation_jobs_device_pending
  ON revocation_jobs(device_id, completed_at);
