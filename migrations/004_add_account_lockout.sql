
ALTER TABLE users
ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0,
ADD COLUMN locked_until TIMESTAMPTZ NULL;

ALTER TABLE users
ADD CONSTRAINT users_failed_login_attempts_check
CHECK (failed_login_attempts >= 0);
