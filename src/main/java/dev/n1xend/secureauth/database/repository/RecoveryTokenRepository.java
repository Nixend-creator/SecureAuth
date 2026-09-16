package dev.n1xend.secureauth.database.repository;

import dev.n1xend.secureauth.database.DatabaseManager;
import dev.n1xend.secureauth.exception.DatabaseException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for password-recovery token records.
 *
 * <p>Only a SHA-256 hash of the token is ever stored — never the raw token —
 * following the same principle as password storage: a database leak alone
 * must not be enough to reset someone's password.
 *
 * <p><b>Timezone safety:</b> expiry is computed on the DB server with
 * {@code DATE_ADD(NOW(), INTERVAL ? MINUTE)} / {@code datetime('now', '+N minutes')},
 * same pattern as {@link SessionRepository}.
 */
public final class RecoveryTokenRepository {

    private final DatabaseManager db;

    public RecoveryTokenRepository(DatabaseManager db) {
        this.db = db;
    }

    /** Stores a fresh token hash for {@code uuid}, replacing any existing one. */
    public void save(UUID uuid, String tokenHash, int ttlMinutes) {
        String del = "DELETE FROM sa_recovery_tokens WHERE uuid = ?";
        String ins = db.isMysql()
                ? "INSERT INTO sa_recovery_tokens (uuid, token_hash, expires_at)"
                        + " VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE))"
                : "INSERT INTO sa_recovery_tokens (uuid, token_hash, expires_at)"
                        + " VALUES (?, ?, datetime('now', '+' || ? || ' minutes'))";
        try (Connection c = db.getConnection()) {
            try (PreparedStatement ps = c.prepareStatement(del)) {
                ps.setString(1, uuid.toString());
                ps.executeUpdate();
            }
            try (PreparedStatement ps = c.prepareStatement(ins)) {
                ps.setString(1, uuid.toString());
                ps.setString(2, tokenHash);
                ps.setInt(3, ttlMinutes);
                ps.executeUpdate();
            }
        } catch (SQLException e) {
            throw new DatabaseException("recovery token save failed: " + uuid, e);
        }
    }

    /** Returns the stored token hash for {@code uuid}, if a non-expired one exists. */
    public Optional<String> findValidHash(UUID uuid) {
        String sql = db.isMysql() ? "SELECT token_hash FROM sa_recovery_tokens WHERE uuid = ? AND expires_at > NOW()"
                : "SELECT token_hash FROM sa_recovery_tokens WHERE uuid = ? AND expires_at > datetime('now')";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, uuid.toString());
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(rs.getString("token_hash")) : Optional.empty();
            }
        } catch (SQLException e) {
            throw new DatabaseException("recovery token lookup failed: " + uuid, e);
        }
    }

    /** Deletes the token for {@code uuid} — called after successful use. */
    public void delete(UUID uuid) {
        String sql = "DELETE FROM sa_recovery_tokens WHERE uuid = ?";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, uuid.toString());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("recovery token delete failed: " + uuid, e);
        }
    }

    /** Removes expired token rows. Returns count deleted. */
    public int deleteExpired() {
        String sql = db.isMysql() ? "DELETE FROM sa_recovery_tokens WHERE expires_at <= NOW()"
                : "DELETE FROM sa_recovery_tokens WHERE expires_at <= datetime('now')";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("recovery token cleanup failed", e);
        }
    }
}
