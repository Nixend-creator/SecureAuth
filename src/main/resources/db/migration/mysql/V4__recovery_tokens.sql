-- V4: Password recovery tokens.
--
-- /recover previously generated and emailed a token but never stored it
-- anywhere, so it could never actually be used to reset a password — the
-- recovery feature was completely non-functional. This table stores a
-- SHA-256 hash of the token (never the raw token itself, same principle as
-- password storage) with a server-computed expiry.
CREATE TABLE IF NOT EXISTS sa_recovery_tokens (
    uuid         VARCHAR(36)  NOT NULL PRIMARY KEY,
    token_hash   VARCHAR(64)  NOT NULL,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   DATETIME     NOT NULL,
    INDEX idx_recovery_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
