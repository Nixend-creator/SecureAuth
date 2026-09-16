package dev.n1xend.secureauth.database;

import org.slf4j.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Lightweight schema migration manager — zero external dependencies.
 *
 * <p>Tracks applied migrations in {@code sa_schema_version}.
 * Idempotent — safe to call on every startup.
 */
public final class MigrationManager {

    private final DatabaseManager db;
    private final String dbType;
    private final Logger log;

    public MigrationManager(DatabaseManager db, String dbType, Logger log) {
        this.db = db;
        this.dbType = dbType;
        this.log = log;
    }

    public void migrate() {
        try (Connection con = db.getConnection()) {
            ensureVersionTable(con);
            // filename = actual SQL file name (without .sql); description = stored in sa_schema_version
            runIfNeeded(con, 1, "initial_schema", "V1__init", "sa_players");
            runIfNeeded(con, 2, "audit_log", "V2__audit_log", "sa_audit_log");
            runIfNeeded(con, 3, "clear_sessions", "V3__clear_sessions", "sa_sessions");
            runIfNeeded(con, 4, "recovery_tokens", "V4__recovery_tokens", "sa_recovery_tokens");
            runIfNeeded(con, 5, "email_verification", "V5__email_verification", "sa_email_pending");
            log.info("[DB] Schema migrations complete.");
        } catch (SQLException | IOException e) {
            throw new RuntimeException("[DB] Migration failed: " + e.getMessage(), e);
        }
    }

    // ── Private ───────────────────────────────────────────────────────────────

    private void ensureVersionTable(Connection con) throws SQLException {
        String ddl = dbType.equals("mysql")
                ? "CREATE TABLE IF NOT EXISTS sa_schema_version (" + "version INT NOT NULL PRIMARY KEY,"
                        + "description VARCHAR(255) NOT NULL,"
                        + "applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP" + ") ENGINE=InnoDB"
                : "CREATE TABLE IF NOT EXISTS sa_schema_version (" + "version INTEGER NOT NULL PRIMARY KEY,"
                        + "description TEXT NOT NULL," + "applied_at TEXT NOT NULL DEFAULT (datetime('now'))" + ")";
        try (Statement st = con.createStatement()) {
            st.execute(ddl);
        }
    }

    private boolean isApplied(Connection con, int version) throws SQLException {
        try (var ps = con.prepareStatement("SELECT 1 FROM sa_schema_version WHERE version = ?")) {
            ps.setInt(1, version);
            try (var rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    /**
     * Verifies that a sentinel table from the migration actually exists.
     * Protects against the case where schema_version was written but DDL failed
     * (e.g. a previous startup with a buggy migration runner).
     */
    private boolean tableExists(Connection con, String tableName) throws SQLException {
        try (var ps = con.prepareStatement("SELECT 1 FROM " + tableName + " WHERE 1=0")) {
            ps.execute();
            return true;
        } catch (SQLException e) {
            return false; // table doesn't exist
        }
    }

    /**
     * @param description   human-readable label stored in {@code sa_schema_version}
     * @param filename      SQL file name inside {@code db/migration/<dbType>/} without {@code .sql}
     * @param sentinelTable a table name that must exist if this migration ran successfully
     *
     * <p><strong>IMPORTANT for anyone adding a new migration:</strong> every
     * statement in every {@code .sql} script under {@code db/migration/}
     * MUST be idempotent (safe to execute more than once) — e.g.
     * {@code CREATE TABLE IF NOT EXISTS}, {@code TRUNCATE TABLE} (safe to
     * re-run on an already-empty table), or {@code INSERT ... ON DUPLICATE
     * KEY UPDATE} instead of a bare {@code INSERT}.
     *
     * <p>Why this matters: this method wraps each migration in a JDBC
     * transaction with {@code rollback()} on failure, but <strong>MySQL/
     * MariaDB DDL statements (CREATE TABLE, ALTER TABLE, etc.) always cause
     * an implicit commit before executing, regardless of
     * {@code setAutoCommit(false)}</strong> — a well-known InnoDB limitation.
     * If a script has three CREATE TABLE statements and the third one fails,
     * the first two are ALREADY permanently committed; {@code rollback()}
     * only undoes the (non-DDL) {@code sa_schema_version} insert. On the next
     * startup, this migration has no version record, so the ENTIRE script
     * runs again from the top — which is only safe if every statement in it
     * tolerates being executed against a database where some or all of its
     * effects already happened. Every migration shipped with this project
     * follows this rule today; a future migration that doesn't (e.g. a bare
     * {@code ALTER TABLE ... ADD COLUMN} with no existence check) would fail
     * with "column already exists" on every subsequent startup after a
     * single partial failure, permanently preventing the plugin from
     * starting until someone manually fixes the database by hand.
     */
    private void runIfNeeded(Connection con, int version, String description, String filename, String sentinelTable)
            throws SQLException, IOException {

        if (isApplied(con, version)) {
            // Double-check: the version record exists but did the DDL actually run?
            if (tableExists(con, sentinelTable)) {
                log.debug("[DB] Migration V{} already applied — skipping.", version);
                return;
            }
            // Schema record exists but tables are missing — previous migration was corrupt.
            // Delete the record and re-run.
            log.warn("[DB] Migration V{} is recorded but tables are missing — re-running.", version);
            try (var ps = con.prepareStatement("DELETE FROM sa_schema_version WHERE version = ?")) {
                ps.setInt(1, version);
                ps.executeUpdate();
            }
        }

        String resource = "db/migration/" + dbType + "/" + filename + ".sql";
        List<String> statements = parseSql(loadResource(resource));

        if (statements.isEmpty()) {
            throw new IOException("Migration script parsed to zero statements: " + resource);
        }

        log.info("[DB] Running migration V{}: {} ({} statements)...", version, description, statements.size());

        con.setAutoCommit(false);
        try (Statement st = con.createStatement()) {
            for (String sql : statements) {
                log.debug("[DB] SQL: {}", sql.length() > 100 ? sql.substring(0, 100) + "..." : sql);
                st.execute(sql);
            }
            try (var ps = con.prepareStatement("INSERT INTO sa_schema_version (version, description) VALUES (?, ?)")) {
                ps.setInt(1, version);
                ps.setString(2, description);
                ps.executeUpdate();
            }
            con.commit();
            log.info("[DB] Migration V{} applied successfully.", version);
        } catch (SQLException e) {
            con.rollback();
            throw new SQLException("Migration V" + version + " failed and was rolled back: " + e.getMessage(), e);
        } finally {
            con.setAutoCommit(true);
        }
    }

    /**
     * Parses a SQL script into individual executable statements.
     *
     * <ul>
     *   <li>Lines starting with {@code --} are treated as comments and skipped.
     *   <li>Statements are accumulated line-by-line and split on {@code ;} at end of line.
     *   <li>Trailing semicolons are stripped — JDBC does not accept them.
     * </ul>
     */
    static List<String> parseSql(String script) {
        List<String> result = new ArrayList<>();
        StringBuilder current = new StringBuilder();

        for (String line : script.split("\n")) {
            String stripped = line.strip();
            if (stripped.isEmpty() || stripped.startsWith("--"))
                continue;

            if (stripped.endsWith(";")) {
                // Append without the semicolon
                current.append(stripped, 0, stripped.length() - 1).append(" ");
                String stmt = current.toString().strip();
                if (!stmt.isEmpty())
                    result.add(stmt);
                current.setLength(0);
            } else {
                current.append(stripped).append(" ");
            }
        }

        String tail = current.toString().strip();
        if (!tail.isEmpty())
            result.add(tail);

        return result;
    }

    private String loadResource(String path) throws IOException {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(path)) {
            if (is == null) {
                throw new IOException("Migration script not found in jar: " + path);
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                StringBuilder sb = new StringBuilder();
                String line;
                // Read line-by-line to avoid Collectors dependency
                while ((line = reader.readLine()) != null) {
                    if (sb.length() > 0)
                        sb.append('\n');
                    sb.append(line);
                }
                return sb.toString();
            }
        }
    }
}
