package dev.n1xend.secureauth.database.repository;

import dev.n1xend.secureauth.database.DatabaseManager;
import dev.n1xend.secureauth.exception.DatabaseException;
import dev.n1xend.secureauth.player.PlayerData;

import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Optional;
import java.util.UUID;

/** Repository for player authentication records. All methods are blocking — call from async threads. */
public final class PlayerRepository {

    private final DatabaseManager db;

    public PlayerRepository(DatabaseManager db) {
        this.db = db;
    }

    /** Returns player data or empty if not registered. */
    public Optional<PlayerData> findByUuid(UUID uuid) {
        String sql = "SELECT * FROM sa_players WHERE uuid = ?";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, uuid.toString());
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next())
                    return Optional.of(mapRow(rs));
            }
        } catch (SQLException e) {
            throw new DatabaseException("findByUuid failed: " + uuid, e);
        }
        return Optional.empty();
    }

    /** Returns player data or empty if not registered. */
    public Optional<PlayerData> findByUsername(String username) {
        String sql = "SELECT * FROM sa_players WHERE LOWER(username) = LOWER(?)";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next())
                    return Optional.of(mapRow(rs));
            }
        } catch (SQLException e) {
            throw new DatabaseException("findByUsername failed: " + username, e);
        }
        return Optional.empty();
    }

    public void insert(PlayerData data) {
        String sql = """
                INSERT INTO sa_players (uuid, username, password_hash, email, ip_address)
                VALUES (?, ?, ?, ?, ?)
                """;
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, data.uuid().toString());
            ps.setString(2, data.username());
            ps.setString(3, data.passwordHash());
            ps.setString(4, data.email());
            ps.setString(5, data.ipAddress());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("insert player failed: " + data.uuid(), e);
        }
    }

    public void updatePassword(UUID uuid, String newHash) {
        String sql = "UPDATE sa_players SET password_hash = ? WHERE uuid = ?";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, newHash);
            ps.setString(2, uuid.toString());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("updatePassword failed: " + uuid, e);
        }
    }

    /**
     * Updates the recovery email linked to an account.
     *
     * <p>Called only after the new address has been verified via a
     * confirmation token (see {@code /setemail confirm} in {@code AuthCommand}
     * and {@code EmailChangeRepository}) — this method itself performs no
     * verification, so callers must not expose it directly to unauthenticated
     * or unverified input.
     */
    public void updateEmail(UUID uuid, String email) {
        String sql = "UPDATE sa_players SET email = ? WHERE uuid = ?";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, email);
            ps.setString(2, uuid.toString());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("updateEmail failed: " + uuid, e);
        }
    }

    public void updateLastLogin(UUID uuid, String ip) {
        // Use a Java-side timestamp for SQLite/MySQL compatibility (NOW() is MySQL-only).
        String now = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        String sql = "UPDATE sa_players SET last_login_at = ?, last_login_ip = ? WHERE uuid = ?";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, now);
            ps.setString(2, ip);
            ps.setString(3, uuid.toString());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException("updateLastLogin failed: " + uuid, e);
        }
    }

    public boolean isRegistered(UUID uuid) {
        String sql = "SELECT 1 FROM sa_players WHERE uuid = ?";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, uuid.toString());
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            throw new DatabaseException("isRegistered failed: " + uuid, e);
        }
    }

    private PlayerData mapRow(ResultSet rs) throws SQLException {
        return new PlayerData(UUID.fromString(rs.getString("uuid")), rs.getString("username"),
                rs.getString("password_hash"), rs.getString("email"), rs.getString("ip_address"),
                rs.getString("registered_at"), rs.getString("last_login_at"), rs.getString("last_login_ip"));
    }
}
