-- V4: Password recovery tokens (see mysql/V4 for rationale).
CREATE TABLE IF NOT EXISTS sa_recovery_tokens (
    uuid         TEXT NOT NULL PRIMARY KEY,
    token_hash   TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_recovery_expires ON sa_recovery_tokens(expires_at);
