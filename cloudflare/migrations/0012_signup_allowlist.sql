-- Permit individual test users without redeploying the Worker or committing
-- personal email addresses to configuration. Existing configuration entries
-- remain a backwards-compatible bootstrap path.
CREATE TABLE signup_allowlist (
  email TEXT PRIMARY KEY COLLATE NOCASE,
  created_at INTEGER NOT NULL,
  CHECK(email = lower(trim(email))),
  CHECK(length(email) BETWEEN 3 AND 200),
  CHECK(instr(email, '@') > 1)
);

CREATE INDEX signup_allowlist_created
  ON signup_allowlist(created_at DESC);
