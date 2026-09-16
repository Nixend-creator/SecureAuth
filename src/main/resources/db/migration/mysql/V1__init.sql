-- SecureAuth: Initial schema (MySQL)
CREATE TABLE IF NOT EXISTS sa_players (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    uuid         VARCHAR(36)  NOT NULL UNIQUE,
    username     VARCHAR(16)  NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email        VARCHAR(255) DEFAULT NULL,
    ip_address   VARCHAR(45)  NOT NULL,
    registered_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at DATETIME    DEFAULT NULL,
    last_login_ip VARCHAR(45) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS sa_sessions (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    uuid         VARCHAR(36)  NOT NULL,
    ip_address   VARCHAR(45)  NOT NULL,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   DATETIME     NOT NULL,
    INDEX idx_uuid (uuid),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sa_totp (
    uuid         VARCHAR(36)  NOT NULL PRIMARY KEY,
    secret       VARCHAR(64)  NOT NULL,
    enabled      TINYINT(1)   NOT NULL DEFAULT 0,
    backup_codes TEXT         DEFAULT NULL,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sa_ip_bans (
    ip_address   VARCHAR(45)  NOT NULL PRIMARY KEY,
    reason       VARCHAR(255) NOT NULL DEFAULT 'Too many failed attempts',
    banned_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   DATETIME     DEFAULT NULL,
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sa_login_attempts (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    uuid         VARCHAR(36)  NOT NULL,
    ip_address   VARCHAR(45)  NOT NULL,
    success      TINYINT(1)   NOT NULL DEFAULT 0,
    attempted_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_uuid_time (uuid, attempted_at),
    INDEX idx_ip_time (ip_address, attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
