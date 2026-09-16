-- SecureAuth: Audit log table (V2)

CREATE TABLE IF NOT EXISTS sa_audit_log (
    id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event      VARCHAR(32)  NOT NULL,
    uuid       VARCHAR(36)  NOT NULL,
    username   VARCHAR(16)  NOT NULL,
    ip_address VARCHAR(45)  NOT NULL,
    details    VARCHAR(255) DEFAULT NULL,
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_uuid_time  (uuid, created_at),
    INDEX idx_event_time (event, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
