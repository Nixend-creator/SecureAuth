-- V5: Email-change verification tokens.
--
-- Closes a critical gap: /recover previously accepted an arbitrary email
-- address as a command argument and sent the reset token there with zero
-- check against the account's actual linked email (which was, until now,
-- never even settable — always NULL). This meant anyone who could connect
-- as a given Minecraft account (exactly the scenario SecureAuth's password
-- is meant to guard against — shared accounts, stolen sessions, offline-mode
-- name-claiming) could self-service a password reset via /recover without
-- ever proving ownership of anything.
--
-- The fix: an email can only be linked to an account via /setemail, which
-- requires the player to already be authenticated (know their current
-- password) AND confirm receipt of a token at the new address before it is
-- saved. /recover then always sends to the on-file address only — it never
-- accepts a destination as user input again.
CREATE TABLE IF NOT EXISTS sa_email_pending (
    uuid         VARCHAR(36)  NOT NULL PRIMARY KEY,
    email        VARCHAR(255) NOT NULL,
    token_hash   VARCHAR(64)  NOT NULL,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   DATETIME     NOT NULL,
    INDEX idx_email_pending_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
