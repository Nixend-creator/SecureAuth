package dev.n1xend.secureauth.database;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import dev.n1xend.secureauth.config.PluginConfig;
import dev.n1xend.secureauth.exception.DatabaseException;
import org.bukkit.plugin.java.JavaPlugin;
import org.slf4j.Logger;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * Manages database connections via HikariCP and schema migrations via Flyway.
 *
 * <p><strong>Important:</strong> Never recreate the pool at runtime. The pool is
 * created once in {@link #connect()} and closed in {@link #close()}.
 */
public final class DatabaseManager {

    private final JavaPlugin plugin;
    private final PluginConfig config;
    private final Logger log;

    private HikariDataSource dataSource;

    public DatabaseManager(JavaPlugin plugin, PluginConfig config, Logger log) {
        this.plugin = plugin;
        this.config = config;
        this.log = log;
    }

    /**
     * Creates the HikariCP connection pool.
     *
     * @return {@code true} on success
     */
    public boolean connect() {
        try {
            PluginConfig.DatabaseConfig db = config.getDatabase();
            HikariConfig hikari = new HikariConfig();

            if (db.isSqlite()) {
                configureSqlite(hikari);
            } else {
                configureMysql(hikari, db);
            }

            dataSource = new HikariDataSource(hikari);
            log.info("[DB] Connected via {} (pool={})", db.type(), db.isSqlite() ? 1 : db.poolSize());
            return true;
        } catch (Exception e) {
            log.error("[DB] Connection failed: {}", e.getMessage(), e);
            return false;
        }
    }

    /** Runs schema migrations via the built-in {@link MigrationManager}. */
    public void migrate() {
        new MigrationManager(this, config.getDatabase().type(), log).migrate();
    }

    /** Returns a connection from the pool. Caller must close it (use try-with-resources). */
    public Connection getConnection() throws SQLException {
        if (dataSource == null || dataSource.isClosed()) {
            throw new DatabaseException("DataSource is not available");
        }
        return dataSource.getConnection();
    }

    /** Closes the connection pool. Called during graceful shutdown. */
    public void close() {
        if (dataSource != null && !dataSource.isClosed()) {
            dataSource.close();
            log.info("[DB] Connection pool closed.");
        }
    }

    public boolean isConnected() {
        return dataSource != null && !dataSource.isClosed();
    }

    /**
     * Returns the number of connections currently in use by the pool.
     * Used by {@link dev.n1xend.secureauth.shutdown.ShutdownManager} to wait
     * until all pending virtual-thread DB writes have completed before closing.
     */
    public int getActiveConnections() {
        if (dataSource == null || dataSource.isClosed())
            return 0;
        return dataSource.getHikariPoolMXBean().getActiveConnections();
    }

    /** Returns true if this is a MySQL/MariaDB connection. */
    public boolean isMysql() {
        return config.getDatabase().isMysql();
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private void configureSqlite(HikariConfig hikari) {
        plugin.getDataFolder().mkdirs();
        String path = plugin.getDataFolder().getAbsolutePath() + "/data.db";
        hikari.setDriverClassName("org.sqlite.JDBC");
        hikari.setJdbcUrl("jdbc:sqlite:" + path);
        // SQLite: single writer — pool size MUST be 1
        hikari.setMaximumPoolSize(1);
        hikari.setMinimumIdle(1);
        hikari.setPoolName("SecureAuth-SQLite");
        hikari.addDataSourceProperty("journal_mode", "WAL");
        hikari.addDataSourceProperty("synchronous", "NORMAL");
        hikari.addDataSourceProperty("foreign_keys", "true");
    }

    private void configureMysql(HikariConfig hikari, PluginConfig.DatabaseConfig db) {
        // serverTimezone=UTC is mandatory: without it the connector inherits the JVM
        // system timezone which may differ from the DB server timezone.  When they
        // diverge, every DATETIME comparison such as "expires_at > NOW()" silently
        // misfires — sessions appear expired the moment they are created.
        //
        // useSSL: defaults to false for backward compatibility (many self-hosted
        // MySQL/MariaDB instances have no TLS certificate configured, and forcing
        // this on by default would break existing installs at startup). When false
        // AND the DB host isn't local, all traffic — password hashes, TOTP secrets,
        // session rows — crosses the network in plaintext. See the startup warning
        // in SecureAuthPlugin#onEnable for when this is flagged to the operator.
        String sslParam = db.useSsl() ? "&useSSL=true&requireSSL=true&verifyServerCertificate=true" : "&useSSL=false";
        hikari.setJdbcUrl(String.format("jdbc:mysql://%s:%d/%s?allowPublicKeyRetrieval=true&serverTimezone=UTC%s",
                db.host(), db.port(), db.database(), sslParam));
        hikari.setUsername(db.username());
        hikari.setPassword(db.password());
        hikari.setMaximumPoolSize(db.poolSize());
        hikari.setConnectionTimeout(db.connectionTimeout());
        hikari.setIdleTimeout(db.idleTimeout());
        hikari.setMaxLifetime(db.maxLifetime());
        hikari.setPoolName("SecureAuth-MySQL");
        hikari.addDataSourceProperty("cachePrepStmts", "true");
        hikari.addDataSourceProperty("prepStmtCacheSize", "250");
        hikari.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");
        hikari.addDataSourceProperty("useServerPrepStmts", "true");
    }
}
