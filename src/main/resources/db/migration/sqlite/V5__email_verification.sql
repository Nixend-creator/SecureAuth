-- V5: Email-change verification tokens (see mysql/V5 for rationale).
CREATE TABLE IF NOT EXISTS sa_email_pending (
    uuid         TEXT NOT NULL PRIMARY KEY,
    email        TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email_pending_expires ON sa_email_pending(expires_at);
