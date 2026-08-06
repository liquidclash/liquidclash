-- Replace password authentication with single-use email and OIDC challenges.
-- The legacy password columns remain only because SQLite cannot drop them
-- safely in-place on an already deployed D1 database.
CREATE TABLE auth_identities (
  provider TEXT NOT NULL CHECK(provider IN ('email', 'apple', 'google')),
  subject TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email TEXT COLLATE NOCASE,
  email_verified_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(provider, subject),
  UNIQUE(provider, user_id)
);

INSERT INTO auth_identities(
  provider, subject, user_id, email, email_verified_at, created_at, updated_at
)
SELECT 'email', lower(email), id, lower(email), created_at, created_at, updated_at
FROM users;

CREATE TABLE auth_challenges (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('email_otp', 'apple', 'google')),
  email TEXT COLLATE NOCASE,
  secret_hash TEXT NOT NULL,
  invitation_id TEXT REFERENCES invitations(id) ON DELETE SET NULL,
  installation_id TEXT NOT NULL,
  device_name TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
  max_attempts INTEGER NOT NULL CHECK(max_attempts BETWEEN 1 AND 20),
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  created_at INTEGER NOT NULL
);

CREATE INDEX auth_challenges_expiry
  ON auth_challenges(expires_at, consumed_at);
CREATE INDEX auth_challenges_email
  ON auth_challenges(kind, email, created_at);
CREATE INDEX auth_identities_user
  ON auth_identities(user_id);

-- Destroy reusable password verifiers as part of the one-way passwordless
-- migration. Email OTP remains available to every existing account.
UPDATE users
SET password_hash = 'PASSWORD_AUTH_DISABLED',
    password_salt = 'PASSWORD_AUTH_DISABLED',
    updated_at = MAX(updated_at, unixepoch());
