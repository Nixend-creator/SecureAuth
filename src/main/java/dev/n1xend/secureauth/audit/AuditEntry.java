package dev.n1xend.secureauth.audit;

/**
 * A single audit log record read from {@code sa_audit_log}.
 *
 * @param event     event type
 * @param uuid      player UUID string
 * @param username  player name at the time of event
 * @param ip        IP address
 * @param details   optional extra info (e.g. ban reason, admin name)
 * @param createdAt ISO datetime string
 */
public record AuditEntry(AuditEvent event, String uuid, String username, String ip, String details, String createdAt) {
}
