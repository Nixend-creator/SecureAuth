package dev.n1xend.secureauth.database.repository;

import dev.n1xend.secureauth.database.DatabaseManager;
import dev.n1xend.secureauth.exception.DatabaseException;

import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/** Repository for IP ban records. */
public final class IpBanRepository {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final DatabaseManager db;

    public IpBanRepository(DatabaseManager db) {
        this.db = db;
    }

    public boolean isBanned(String ip) {
        String sql = "SELECT 1 FROM sa_ip_bans WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > ?)";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, ip);
            ps.setString(2, LocalDateTime.now().format(FMT));
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw new DatabaseException("isBanned check failed: " + ip, e);
        }
    }

    /**
     * Inserts or updates a ban record.
     *
     * <p><strong>Bug history:</strong> this previously used a single,
     * SQLite-only upsert statement (<code>ON CONFLICT(...) DO UPDATE SET
     * ... = excluded....</code>) for BOTH database types — every other
     * repository in this project correctly branches on {@link
     * DatabaseManager#isMysql()} for exactly this reason (upsert syntax is
     * one of the most database-specific features in SQL), but this one
     * didn't. MySQL/MariaDB has no {@code ON CONFLICT}/{@code excluded}
     * syntax at all — every call to this method threw a SQL syntax error on
     * a MySQL/MariaDB backend, meaning the entire IP-ban system (both
     * AntiBot's own internal bans and the public {@code AntiBotApi.banIp()})
     * was completely non-functional in production for any server using
     * MySQL rather than SQLite.
     */
    public void ban(String ip, String reason, LocalDateTime expiresAt) {
        String sql = db.isMysql() ? """
                INSERT INTO sa_ip_bans (ip_address, reason, expires_at)
                VALUES (?, ?, ?)
                ON DUPLICATE KEY UPDATE reason = VALUES(reason), expires_at = VALUES(expires_at)
                """ : """
                INSERT INTO sa_ip_bans (ip_address, reason, expires_at)
                VALUES (?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET reason=excluded.reason, expires_at=excluded.expires_at
                """;
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, ip);
            ps.setString(2, reason);
            ps.setString(3, expiresAt != null ? expiresAt.format(FMT) : null);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("ban failed: " + ip, e);
        }
    }

    public void unban(String ip) {
        String sql = "DELETE FROM sa_ip_bans WHERE ip_address = ?";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, ip);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("unban failed: " + ip, e);
        }
    }

    /** Removes expired bans (maintenance task). */
    public int deleteExpired() {
        String sql = "DELETE FROM sa_ip_bans WHERE expires_at IS NOT NULL AND expires_at <= ?";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, LocalDateTime.now().format(FMT));
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("deleteExpiredBans failed", e);
        }
    }
}
