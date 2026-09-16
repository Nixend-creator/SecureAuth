package dev.n1xend.secureauth.database.repository;

import dev.n1xend.secureauth.database.DatabaseManager;
import dev.n1xend.secureauth.exception.DatabaseException;

import java.sql.*;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for player session records.
 *
 * <p><b>Timezone safety:</b> no Java {@code LocalDateTime} values are ever
 * sent to the database.  All expiry timestamps are computed on the DB server
 * with {@code DATE_ADD(NOW(), INTERVAL ? MINUTE)} (MySQL/MariaDB) or
 * {@code datetime('now', '+N minutes')} (SQLite), and expiry checks use
 * {@code NOW()} / {@code datetime('now')} on the server side as well.
 * This eliminates the JVM ↔ DB timezone mismatch that caused sessions to
 * appear expired immediately after creation.
 */
public final class SessionRepository {

    private final DatabaseManager db;

    public SessionRepository(DatabaseManager db) {
        this.db = db;
    }

    /**
     * Inserts a fresh session for {@code uuid}, replacing any existing one.
     *
     * @param uuid       player UUID
     * @param ip         client IP address
     * @param ttlMinutes session lifetime in minutes, computed on the DB server
     */
    public void upsert(UUID uuid, String ip, int ttlMinutes) {
        String del = "DELETE FROM sa_sessions WHERE uuid = ?";
        // expires_at is calculated entirely on the DB server — no Java datetime involved.
        String ins = db.isMysql()
                ? "INSERT INTO sa_sessions (uuid, ip_address, expires_at)"
                        + " VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE))"
                : "INSERT INTO sa_sessions (uuid, ip_address, expires_at)"
                        + " VALUES (?, ?, datetime('now', '+' || ? || ' minutes'))";

        try (Connection c = db.getConnection()) {
            try (PreparedStatement ps = c.prepareStatement(del)) {
                ps.setString(1, uuid.toString());
                ps.executeUpdate();
            }
            try (PreparedStatement ps = c.prepareStatement(ins)) {
                ps.setString(1, uuid.toString());
                ps.setString(2, ip);
                ps.setInt(3, ttlMinutes);
                ps.executeUpdate();
            }
        } catch (SQLException e) {
            throw new DatabaseException("session upsert failed: " + uuid, e);
        }
    }

    /**
     * Full session details for the self-service {@code /session} command —
     * unlike {@link #findValidSessionIp}, returns ANY session row for the
     * account (even an already-expired one, so a player can see "your last
     * trusted session expired at ..." rather than just "no session").
     */
    public record SessionInfo(String ip, String createdAt, String expiresAt, boolean expired) {
    }

    /** Returns full session details for {@code uuid}, if any session row exists at all. */
    public Optional<SessionInfo> findSessionInfo(UUID uuid) {
        String sql = db.isMysql()
                ? "SELECT ip_address, created_at, expires_at, (expires_at <= NOW()) AS expired"
                        + " FROM sa_sessions WHERE uuid = ?"
                : "SELECT ip_address, created_at, expires_at, (expires_at <= datetime('now')) AS expired"
                        + " FROM sa_sessions WHERE uuid = ?";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, uuid.toString());
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next())
                    return Optional.empty();
                return Optional.of(new SessionInfo(rs.getString("ip_address"), rs.getString("created_at"),
                        rs.getString("expires_at"), rs.getBoolean("expired")));
            }
        } catch (SQLException e) {
            throw new DatabaseException("findSessionInfo failed: " + uuid, e);
        }
    }

    /**
     * Returns the stored IP if a non-expired session exists for {@code uuid}.
     * Expiry is checked on the DB server with {@code NOW()} — no Java timestamp sent.
     */
    public Optional<String> findValidSessionIp(UUID uuid) {
        String sql = db.isMysql() ? "SELECT ip_address FROM sa_sessions WHERE uuid = ? AND expires_at > NOW()"
                : "SELECT ip_address FROM sa_sessions WHERE uuid = ? AND expires_at > datetime('now')";

        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, uuid.toString());
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(rs.getString("ip_address")) : Optional.empty();
            }
        } catch (SQLException e) {
            throw new DatabaseException("findValidSessionIp failed: " + uuid, e);
        }
    }

    /** Deletes the session for {@code uuid} (called on logout or password change). */
    public void delete(UUID uuid) {
        String sql = "DELETE FROM sa_sessions WHERE uuid = ?";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, uuid.toString());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("session delete failed: " + uuid, e);
        }
    }

    /** Removes all expired sessions. Returns the number of rows deleted. */
    public int deleteExpired() {
        String sql = db.isMysql() ? "DELETE FROM sa_sessions WHERE expires_at <= NOW()"
                : "DELETE FROM sa_sessions WHERE expires_at <= datetime('now')";

        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("deleteExpiredSessions failed", e);
        }
    }
}
