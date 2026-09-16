package dev.n1xend.secureauth.audit;

import dev.n1xend.secureauth.database.DatabaseManager;
import dev.n1xend.secureauth.exception.DatabaseException;
import org.slf4j.Logger;

import java.sql.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Records and retrieves auth events from {@code sa_audit_log}.
 *
 * <p><b>Writes</b> are fire-and-forget on virtual threads — caller never blocks.
 * <b>Reads</b> are synchronous — call from an async/virtual thread.
 */
public final class AuditLogService {

    /** Rows returned per {@link #getHistory} call. */
    private static final int MAX_ROWS = 20;

    /** Max rows kept per player; oldest pruned on each write. */
    private static final int RETAIN_ROWS = 200;

    private final DatabaseManager db;
    private final Logger log;

    public AuditLogService(DatabaseManager db, Logger log) {
        this.db = db;
        this.log = log;
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    /** Records an event asynchronously. Never throws. details may be null. */
    public void logAsync(AuditEvent event, UUID uuid, String username, String ip, String details) {
        Thread.startVirtualThread(() -> {
            try {
                insert(event, uuid.toString(), username, ip, details);
                prune(uuid.toString());
            } catch (Exception e) {
                log.warn("[Audit] Failed to record {}: {}", event, e.getMessage());
            }
        });
    }

    /** Convenience — no details. */
    public void logAsync(AuditEvent event, UUID uuid, String username, String ip) {
        logAsync(event, uuid, username, ip, null);
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    /**
     * Returns the last {@value MAX_ROWS} audit entries for {@code uuid}, newest first.
     * Blocking — must be called from a virtual/async thread.
     */
    public List<AuditEntry> getHistory(UUID uuid) {
        String sql = """
                SELECT event, uuid, username, ip_address, details, created_at
                FROM sa_audit_log
                WHERE uuid = ?
                ORDER BY created_at DESC
                LIMIT ?
                """;
        List<AuditEntry> result = new ArrayList<>();
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, uuid.toString());
            ps.setInt(2, MAX_ROWS);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next())
                    result.add(mapRow(rs));
            }
        } catch (SQLException e) {
            throw new DatabaseException("getHistory failed: " + uuid, e);
        }
        return result;
    }

    /**
     * Returns the number of {@code LOGIN_FAIL} events for {@code uuid} within
     * the last {@code minutes} minutes — the persistent, cross-session
     * counterpart to {@code AuthState.getFailedAttempts()}.
     *
     * <p>Why this exists: {@code AuthState} (and its failed-attempt counter)
     * is created fresh for every new connection — reconnecting resets it to
     * zero. Without a persistent check backing it, {@code
     * security.max-login-attempts} only limited guesses within a single
     * connection: a script could hit the limit, disconnect, immediately
     * reconnect to a brand-new {@code AuthState}, and keep guessing
     * indefinitely — the only thing actually stopping it being AntiBot's
     * separate, IP-keyed ban system, not this account-level setting at all.
     * This reuses {@code sa_audit_log} (already durably written on every
     * failed login, see {@code AuditEvent.LOGIN_FAIL}) rather than the
     * unrelated {@code sa_login_attempts} table, which nothing writes to.
     *
     * <p><strong>Password-change reset:</strong> only counts failures that
     * happened AFTER the account's most recent {@code PASSWORD_CHANGE} or
     * {@code PASSWORD_RESET} event (if any). Without this, a player who was
     * legitimately locked out, then recovered their account via
     * {@code /recover confirm} or fixed a forgotten password via
     * {@code /changepassword}, would be immediately re-locked on their very
     * next login attempt — even with the correct NEW password — since the
     * old {@code LOGIN_FAIL} timestamps never went anywhere. Changing the
     * password is the standard, expected way to clear an account lockout;
     * this makes that actually work rather than trapping a legitimate user
     * who just proved they regained control of the account.
     *
     * <p>Blocking — call from a virtual/async thread.
     */
    public int countRecentFailures(UUID uuid, int minutes) {
        String sql = db.isMysql()
                ? "SELECT COUNT(*) FROM sa_audit_log WHERE uuid = ? AND event = 'LOGIN_FAIL'"
                        + " AND created_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)"
                        + " AND created_at > COALESCE((SELECT MAX(created_at) FROM sa_audit_log"
                        + "   WHERE uuid = ? AND event IN ('PASSWORD_CHANGE', 'PASSWORD_RESET')), '1970-01-01')"
                : "SELECT COUNT(*) FROM sa_audit_log WHERE uuid = ? AND event = 'LOGIN_FAIL'"
                        + " AND created_at > datetime('now', '-' || ? || ' minutes')"
                        + " AND created_at > COALESCE((SELECT MAX(created_at) FROM sa_audit_log"
                        + "   WHERE uuid = ? AND event IN ('PASSWORD_CHANGE', 'PASSWORD_RESET')), '1970-01-01')";
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, uuid.toString());
            ps.setInt(2, minutes);
            ps.setString(3, uuid.toString());
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        } catch (SQLException e) {
            throw new DatabaseException("countRecentFailures failed: " + uuid, e);
        }
    }

    /**
     * Returns server-wide statistics snapshot for {@code /saadmin stats}.
     * Uses separate single-table queries for SQLite/MySQL compatibility.
     * Blocking — call from async thread.
     */
    public Stats getStats(int onlinePlayers) {
        try (Connection c = db.getConnection()) {
            int totalPlayers = queryInt(c, "SELECT COUNT(*) FROM sa_players");
            int activeSessions = queryInt(c, db.isMysql() ? "SELECT COUNT(*) FROM sa_sessions WHERE expires_at > NOW()"
                    : "SELECT COUNT(*) FROM sa_sessions WHERE expires_at > datetime('now')");
            int activeBans = queryInt(c, "SELECT COUNT(*) FROM sa_ip_bans WHERE expires_at IS NULL OR expires_at > ?",
                    // Match IpBanRepository.isBanned()'s time source exactly (JVM-local
                    // LocalDateTime.now()), not DB-side NOW()/datetime('now'). Using the
                    // DB-side time here would silently disagree with what actually gets
                    // enforced whenever the JVM's system timezone isn't UTC — SQLite's
                    // datetime('now') specifically returns UTC, so on any non-UTC SQLite
                    // host this count would previously have been flat-out wrong relative
                    // to which bans are ACTUALLY still active, even though enforcement
                    // itself was fine (a display/reporting bug, not a security one).
                    LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
            int failsLastHour = queryInt(c, db.isMysql()
                    ? "SELECT COUNT(*) FROM sa_audit_log WHERE event='LOGIN_FAIL' AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)"
                    : "SELECT COUNT(*) FROM sa_audit_log WHERE event='LOGIN_FAIL' AND created_at >= datetime('now','-1 hour')");
            int registrationsToday = queryInt(c, db.isMysql()
                    ? "SELECT COUNT(*) FROM sa_audit_log WHERE event='REGISTER' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
                    : "SELECT COUNT(*) FROM sa_audit_log WHERE event='REGISTER' AND created_at >= datetime('now','-24 hours')");

            return new Stats(totalPlayers, onlinePlayers, activeSessions, activeBans, failsLastHour,
                    registrationsToday);
        } catch (SQLException e) {
            throw new DatabaseException("getStats failed", e);
        }
    }

    /**
     * Returns all active (non-expired) IP bans, ordered by ban time descending.
     * Blocking — call from async thread.
     */
    public List<BanEntry> getActiveBans() {
        String sql = db.isMysql()
                ? "SELECT ip_address, reason, banned_at, expires_at FROM sa_ip_bans WHERE expires_at IS NULL OR expires_at > NOW() ORDER BY banned_at DESC"
                : "SELECT ip_address, reason, banned_at, expires_at FROM sa_ip_bans WHERE expires_at IS NULL OR expires_at > datetime('now') ORDER BY banned_at DESC";
        List<BanEntry> result = new ArrayList<>();
        try (Connection c = db.getConnection();
                Statement st = c.createStatement();
                ResultSet rs = st.executeQuery(sql)) {
            while (rs.next()) {
                result.add(new BanEntry(rs.getString("ip_address"), rs.getString("reason"), rs.getString("banned_at"),
                        rs.getString("expires_at") // null = permanent
                ));
            }
        } catch (SQLException e) {
            throw new DatabaseException("getActiveBans failed", e);
        }
        return result;
    }

    // ── Private ───────────────────────────────────────────────────────────────

    private void insert(AuditEvent event, String uuid, String username, String ip, String details) throws SQLException {
        String sql = """
                INSERT INTO sa_audit_log (event, uuid, username, ip_address, details)
                VALUES (?, ?, ?, ?, ?)
                """;
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, event.name());
            ps.setString(2, uuid);
            ps.setString(3, username);
            ps.setString(4, ip);
            ps.setString(5, details);
            ps.executeUpdate();
        }
    }

    /** Prunes rows beyond RETAIN_ROWS for a player (keeps newest). */
    private void prune(String uuid) throws SQLException {
        // Wrapping the inner SELECT in a derived table alias ("kept") is required
        // for MariaDB compatibility: MariaDB does not support LIMIT inside a
        // direct NOT IN (SELECT ... LIMIT ?) subquery and throws
        // "This version of MariaDB doesn't yet support 'LIMIT & IN/ALL/ANY/SOME subquery'".
        // The extra SELECT ... FROM (...) AS kept indirection is ignored by the
        // query planner but satisfies the parser on MariaDB, MySQL, and SQLite alike.
        String sql = """
                DELETE FROM sa_audit_log
                WHERE uuid = ?
                  AND id NOT IN (
                      SELECT id FROM (
                          SELECT id FROM sa_audit_log
                          WHERE uuid = ?
                          ORDER BY created_at DESC
                          LIMIT ?
                      ) AS kept
                  )
                """;
        try (Connection c = db.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, uuid);
            ps.setString(2, uuid);
            ps.setInt(3, RETAIN_ROWS);
            ps.executeUpdate();
        }
    }

    /** Executes a no-param COUNT query and returns the integer result. */
    private int queryInt(Connection c, String sql) throws SQLException {
        try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            return rs.next() ? rs.getInt(1) : 0;
        }
    }

    private int queryInt(Connection c, String sql, String param) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, param);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        }
    }

    private AuditEntry mapRow(ResultSet rs) throws SQLException {
        return new AuditEntry(AuditEvent.valueOf(rs.getString("event")), rs.getString("uuid"), rs.getString("username"),
                rs.getString("ip_address"), rs.getString("details"), rs.getString("created_at"));
    }

    // ── Value types ───────────────────────────────────────────────────────────

    /**
     * Server-wide statistics snapshot.
     *
     * @param totalPlayers       registered players in DB
     * @param onlinePlayers      players online right now (from Bukkit)
     * @param activeSessions     non-expired IP sessions
     * @param activeBans         non-expired IP bans
     * @param failsLastHour      LOGIN_FAIL events in past 60 min
     * @param registrationsToday REGISTER events in past 24 h
     */
    public record Stats(int totalPlayers, int onlinePlayers, int activeSessions, int activeBans, int failsLastHour,
            int registrationsToday) {
    }

    /**
     * A single active IP ban record.
     *
     * @param ip        IP address
     * @param reason    reason string
     * @param bannedAt  ISO datetime of ban
     * @param expiresAt ISO datetime of expiry, or {@code null} for permanent
     */
    public record BanEntry(String ip, String reason, String bannedAt, String expiresAt) {
    }
}
