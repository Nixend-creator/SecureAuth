package dev.n1xend.secureauth.database.repository;

import dev.n1xend.secureauth.database.DatabaseManager;
import dev.n1xend.secureauth.exception.DatabaseException;
import dev.n1xend.secureauth.twofa.TotpData;

import java.sql.*;
import java.util.*;

/** Repository for TOTP 2FA data. */
public final class TotpRepository {

    private static final String SEPARATOR = ",";

    private final DatabaseManager db;

    public TotpRepository(DatabaseManager db) {
        this.db = db;
    }

    public Optional<TotpData> find(UUID uuid) {
        String sql = "SELECT * FROM sa_totp WHERE uuid = ?";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, uuid.toString());
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String rawCodes = rs.getString("backup_codes");
                    List<String> codes = rawCodes == null || rawCodes.isBlank() ? List.of()
                            : Arrays.asList(rawCodes.split(SEPARATOR));
                    return Optional.of(new TotpData(uuid, rs.getString("secret"), rs.getBoolean("enabled"), codes));
                }
            }
        } catch (SQLException e) {
            throw new DatabaseException("TotpRepository.find failed: " + uuid, e);
        }
        return Optional.empty();
    }

    public boolean isEnabled(UUID uuid) {
        String sql = "SELECT enabled FROM sa_totp WHERE uuid = ?";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, uuid.toString());
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() && rs.getBoolean("enabled");
            }
        } catch (SQLException e) {
            throw new DatabaseException("TotpRepository.isEnabled failed: " + uuid, e);
        }
    }

    /**
     * Inserts or updates a player's TOTP record (enable/re-enroll 2FA).
     *
     * <p><strong>Bug history:</strong> same class of bug found and fixed in
     * {@code IpBanRepository.ban()} — this previously used a single,
     * SQLite-only upsert statement for BOTH database types. MySQL/MariaDB
     * has no {@code ON CONFLICT}/{@code excluded} syntax at all, so every
     * {@code /2fa enable} confirmation threw a SQL syntax error on a
     * MySQL/MariaDB backend — 2FA setup was completely non-functional in
     * production for any server using MySQL rather than SQLite.
     */
    public void save(UUID uuid, String secret, boolean enabled, List<String> backupCodes) {
        String sql = db.isMysql() ? """
                INSERT INTO sa_totp (uuid, secret, enabled, backup_codes)
                VALUES (?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE secret = VALUES(secret),
                    enabled = VALUES(enabled), backup_codes = VALUES(backup_codes)
                """ : """
                INSERT INTO sa_totp (uuid, secret, enabled, backup_codes)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(uuid) DO UPDATE SET secret=excluded.secret,
                    enabled=excluded.enabled, backup_codes=excluded.backup_codes
                """;
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, uuid.toString());
            ps.setString(2, secret);
            ps.setBoolean(3, enabled);
            ps.setString(4, String.join(SEPARATOR, backupCodes));
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("TotpRepository.save failed: " + uuid, e);
        }
    }

    public void disable(UUID uuid) {
        String sql = "UPDATE sa_totp SET enabled = 0 WHERE uuid = ?";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, uuid.toString());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("TotpRepository.disable failed: " + uuid, e);
        }
    }

    public void updateBackupCodes(UUID uuid, List<String> backupCodes) {
        String sql = "UPDATE sa_totp SET backup_codes = ? WHERE uuid = ?";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, String.join(SEPARATOR, backupCodes));
            ps.setString(2, uuid.toString());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("TotpRepository.updateBackupCodes failed: " + uuid, e);
        }
    }
}
