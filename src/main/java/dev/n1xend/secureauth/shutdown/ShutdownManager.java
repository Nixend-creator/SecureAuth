package dev.n1xend.secureauth.shutdown;

import dev.n1xend.secureauth.database.DatabaseManager;
import dev.n1xend.secureauth.player.PlayerDataService;
import dev.n1xend.secureauth.session.SessionService;
import org.slf4j.Logger;

/**
 * Graceful shutdown sequence per standards v6.0 — 7 steps:
 *
 * <ol>
 * <li>Log shutdown start</li>
 * <li>Flush all player caches (auth state + data cache)</li>
 * <li>Clean expired sessions</li>
 * <li>Wait for pending virtual threads (best-effort, no guarantee)</li>
 * <li>Close database connections</li>
 * <li>Log shutdown complete</li>
 * <li>Return (JVM handles the rest)</li>
 * </ol>
 *
 * <p><strong>Important:</strong> {@code cache.flushAll()} BEFORE closing the DB pool.
 */
public final class ShutdownManager {

    private final PlayerDataService playerData;
    private final SessionService sessions;
    private final DatabaseManager db;
    private final Logger log;

    private volatile boolean shuttingDown = false;

    public ShutdownManager(PlayerDataService playerData, SessionService sessions, DatabaseManager db, Logger log) {
        this.playerData = playerData;
        this.sessions = sessions;
        this.db = db;
        this.log = log;
    }

    public void shutdown() {
        // Step 1
        shuttingDown = true;
        log.info("[Shutdown] Starting graceful shutdown...");

        // Step 2 — Flush caches BEFORE closing DB
        log.info("[Shutdown] Flushing player caches...");
        playerData.flushAll();

        // Step 3 — Clean expired sessions
        try {
            int cleaned = sessions.cleanExpired();
            log.info("[Shutdown] Cleaned {} expired sessions.", cleaned);
        } catch (Exception e) {
            log.warn("[Shutdown] Failed to clean sessions: {}", e.getMessage());
        }

        // Step 4 — Wait for pending virtual-thread DB writes (session.create, etc.)
        //
        // A short, fixed grace period runs FIRST, before polling the pool's active-
        // connection count. getActiveConnections() only reflects connections already
        // checked out — a virtual thread that was just spawned (e.g. by /login or
        // /changepassword) and is still inside the deliberately-slow Argon2 hash has
        // NOT reached db.getConnection() yet, so the poll below would see 0 active
        // connections and consider the drain complete even though that thread is
        // about to try to write. Worst case for /changepassword specifically: the new
        // password hash silently never gets persisted, and the player believes it
        // changed when it didn't. The grace period gives that CPU-bound work a
        // realistic window to reach the connection-acquisition point before we start
        // treating "0 active connections" as meaningful.
        //
        // This remains best-effort, not a guarantee — a sufficiently slow Argon2
        // config combined with a near-instant /stop could still race past both the
        // grace period and the poll window. See CHANGELOG for the fuller writeup.
        try {
            Thread.sleep(500);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
        log.info("[Shutdown] Waiting for pending DB operations...");
        long deadline = System.currentTimeMillis() + 5_000;
        while (System.currentTimeMillis() < deadline) {
            try {
                if (db.getActiveConnections() == 0)
                    break;
                Thread.sleep(50);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        // Step 5 — Close DB pool
        log.info("[Shutdown] Closing database pool...");
        db.close();

        // Step 6
        log.info("[Shutdown] Graceful shutdown complete.");
    }

    public boolean isShuttingDown() {
        return shuttingDown;
    }
}
