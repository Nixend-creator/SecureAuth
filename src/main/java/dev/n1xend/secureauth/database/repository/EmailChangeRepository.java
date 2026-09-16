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
 * Repository for pending (unverified) email-change requests.
 *
 * <p>A row here means "player X wants to link email Y, pending proof they
 * control it." Only a SHA-256 hash of the verification token is stored, same
 * principle as {@link RecoveryTokenRepository}. Once verified, the caller is
 * responsible for copying {@code email} into {@code sa_players.email} via
 * {@link PlayerRepository#updateEmail} and deleting the pending row.
 */
public final class EmailChangeRepository {

    /** One field to carry both the pending email and its token hash back to the caller. */
    public record PendingEmail(String email, String tokenHash) {
    }

    private final DatabaseManager db;

    public EmailChangeRepository(DatabaseManager db) {
        this.db = db;
    }

    /** Stores a fresh pending email + token hash for {@code uuid}, replacing any existing one. */
    public void save(UUID uuid, String email, String tokenHash, int ttlMinutes) {
        String del = "DELETE FROM sa_email_pending WHERE uuid = ?";
        String ins = db.isMysql()
                ? "INSERT INTO sa_email_pending (uuid, email, token_hash, expires_at)"
                        + " VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE))"
                : "INSERT INTO sa_email_pending (uuid, email, token_hash, expires_at)"
                        + " VALUES (?, ?, ?, datetime('now', '+' || ? || ' minutes'))";
        try (Connection c = db.getConnection()) {
            try (PreparedStatement ps = c.prepareStatement(del)) {
                ps.setString(1, uuid.toString());
                ps.executeUpdate();
            }
            try (PreparedStatement ps = c.prepareStatement(ins)) {
                ps.setString(1, uuid.toString());
                ps.setString(2, email);
                ps.setString(3, tokenHash);
                ps.setInt(4, ttlMinutes);
                ps.executeUpdate();
            }
        } catch (SQLException e) {
            throw new DatabaseException("email pending save failed: " + uuid, e);
        }
    }

    /** Returns the pending email + token hash for {@code uuid}, if a non-expired one exists. */
    public Optional<PendingEmail> findValid(UUID uuid) {
        String sql = db.isMysql()
                ? "SELECT email, token_hash FROM sa_email_pending WHERE uuid = ? AND expires_at > NOW()"
                : "SELECT email, token_hash FROM sa_email_pending WHERE uuid = ? AND expires_at > datetime('now')";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, uuid.toString());
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next())
                    return Optional.empty();
                return Optional.of(new PendingEmail(rs.getString("email"), rs.getString("token_hash")));
            }
        } catch (SQLException e) {
            throw new DatabaseException("email pending lookup failed: " + uuid, e);
        }
    }

    /** Deletes the pending request for {@code uuid} — called after verification or replacement. */
    public void delete(UUID uuid) {
        String sql = "DELETE FROM sa_email_pending WHERE uuid = ?";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, uuid.toString());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("email pending delete failed: " + uuid, e);
        }
    }

    /** Removes expired pending rows. Returns count deleted. */
    public int deleteExpired() {
        String sql = db.isMysql() ? "DELETE FROM sa_email_pending WHERE expires_at <= NOW()"
                : "DELETE FROM sa_email_pending WHERE expires_at <= datetime('now')";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("email pending cleanup failed", e);
        }
    }
}
