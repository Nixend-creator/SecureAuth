package dev.n1xend.secureauth.audit;

/**
 * Auth event types recorded in {@code sa_audit_log}.
 */
public enum AuditEvent {
    REGISTER, LOGIN, LOGIN_FAIL, LOGOUT, PASSWORD_CHANGE, PASSWORD_RESET, TOTP_ENABLE, TOTP_DISABLE, SESSION_RESTORE,
    FORCE_LOGIN, IP_BAN, EMAIL_CHANGED
}
