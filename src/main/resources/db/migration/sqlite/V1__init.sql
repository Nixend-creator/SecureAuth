-- SecureAuth: Initial schema (SQLite)

CREATE TABLE IF NOT EXISTS sa_players (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid          TEXT NOT NULL UNIQUE,
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    email         TEXT DEFAULT NULL,
    ip_address    TEXT NOT NULL,
    registered_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_at TEXT DEFAULT NULL,
    last_login_ip TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS sa_sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid       TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_uuid    ON sa_sessions(uuid);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sa_sessions(expires_at);

CREATE TABLE IF NOT EXISTS sa_totp (
    uuid         TEXT NOT NULL PRIMARY KEY,
    secret       TEXT NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 0,
    backup_codes TEXT DEFAULT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sa_ip_bans (
    ip_address TEXT NOT NULL PRIMARY KEY,
    reason     TEXT NOT NULL DEFAULT 'Too many failed attempts',
    banned_at  TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_ipbans_expires ON sa_ip_bans(expires_at);

CREATE TABLE IF NOT EXISTS sa_login_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid         TEXT NOT NULL,
    ip_address   TEXT NOT NULL,
    success      INTEGER NOT NULL DEFAULT 0,
    attempted_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_attempts_uuid ON sa_login_attempts(uuid, attempted_at);
CREATE INDEX IF NOT EXISTS idx_attempts_ip   ON sa_login_attempts(ip_address, attempted_at);
