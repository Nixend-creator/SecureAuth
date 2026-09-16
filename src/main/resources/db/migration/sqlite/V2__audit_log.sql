-- SecureAuth: Audit log table (V2)

CREATE TABLE IF NOT EXISTS sa_audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event      TEXT NOT NULL,
    uuid       TEXT NOT NULL,
    username   TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    details    TEXT DEFAULT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_uuid ON sa_audit_log(uuid, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_event ON sa_audit_log(event, created_at);
