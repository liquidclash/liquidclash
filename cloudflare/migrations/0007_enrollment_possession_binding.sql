-- Bind each issued enrollment to an unguessable machine hostname. The client
-- supplies this value to `tailscale up --hostname`; confirm then requires the
-- server inventory to expose the exact label. This prevents one authenticated
-- Tono device from claiming another pending-tag node whose public identity was
-- observed out of band.
ALTER TABLE devices ADD COLUMN enrollment_hostname TEXT;

CREATE UNIQUE INDEX devices_enrollment_hostname_unique
  ON devices(enrollment_hostname) WHERE enrollment_hostname IS NOT NULL;
