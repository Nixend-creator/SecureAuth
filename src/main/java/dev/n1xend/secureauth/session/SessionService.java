package dev.n1xend.secureauth.session;

import dev.n1xend.secureauth.config.PluginConfig;
import dev.n1xend.secureauth.database.DatabaseManager;
import dev.n1xend.secureauth.database.repository.SessionRepository;
import dev.n1xend.secureauth.debug.DebugLogger;
import dev.n1xend.secureauth.exception.DatabaseException;
import org.slf4j.Logger;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Manages IP-based sessions that persist across quick reconnects.
 *
 * <h3>Threading model</h3>
 * <ul>
 *   <li>{@link #create} — synchronous. Must be called from a background thread
 *       (virtual thread). Blocks until the DB write completes so a rapid
 *       reconnect finds the session already in the DB.</li>
 *   <li>{@link #createAsync} — fire-and-forget TTL refresh on an existing
 *       session (used in onPlayerLogin when session is already valid).</li>
 *   <li>{@link #hasValidSession} — synchronous DB read.</li>
 * </ul>
 */
public final class SessionService {

    private final SessionRepository repo;
    private final PluginConfig config;
    private final Logger log;
    private DebugLogger debug;

    public SessionService(DatabaseManager db, PluginConfig config, Logger log) {
        this.repo = new SessionRepository(db);
        this.config = config;
        this.log = log;
    }

    /** Inject the debug logger after construction (avoids circular dep). */
    public void setDebugLogger(DebugLogger debug) {
        this.debug = debug;
    }

    // ── create ──────────────────────────────────────────────────────────────

    /**
     * Synchronously creates or replaces a session for {@code uuid}.
     *
     * <p><strong>Must be called from a virtual thread, never from the main
     * server thread</strong> — this method performs a blocking DB write.
     */
    public void create(UUID uuid, String ip) {
        int ttl = config.getSecurity().sessionTimeoutMinutes();
        dbg("[Session] create() uuid={} ip={} ttl={}min thread={}", uuid, ip, ttl, Thread.currentThread().getName());
        if (ttl <= 0) {
            log.warn("[Session] session-timeout-minutes is {} — sessions disabled by config.", ttl);
            return;
        }
        try {
            repo.upsert(uuid, ip, ttl);
            dbg("[Session] create() SUCCESS uuid={}", uuid);
        } catch (DatabaseException e) {
            log.warn("[Session] Failed to persist session for {} ({}): {}", uuid, ip, e.getMessage());
        }
    }

    /**
     * Fire-and-forget TTL refresh — used when an already-valid session is
     * found in {@code onPlayerLogin}.  The old record is still valid so a
     * race with the next {@link #hasValidSession} call is harmless.
     */
    public void createAsync(UUID uuid, String ip) {
        int ttl = config.getSecurity().sessionTimeoutMinutes();
        dbg("[Session] createAsync() uuid={} ip={} ttl={}min", uuid, ip, ttl);
        if (ttl <= 0)
            return;
        CompletableFuture.runAsync(() -> {
            try {
                repo.upsert(uuid, ip, ttl);
                dbg("[Session] createAsync() SUCCESS uuid={}", uuid);
            } catch (DatabaseException e) {
                log.warn("[Session] Async refresh failed for {} ({}): {}", uuid, ip, e.getMessage());
            }
        });
    }

    // ── hasValidSession ──────────────────────────────────────────────────────

    /**
     * Returns {@code true} if a non-expired session exists for this player
     * and (when ip-binding is enabled) the stored IP matches {@code ip}.
     */
    public boolean hasValidSession(UUID uuid, String ip) {
        dbg("[Session] hasValidSession() uuid={} ip={} ip-binding={}", uuid, ip,
                config.getSecurity().sessionIpBinding());
        try {
            Optional<String> stored = repo.findValidSessionIp(uuid);
            if (stored.isEmpty()) {
                dbg("[Session] hasValidSession() → NO RECORD in DB for uuid={}", uuid);
                return false;
            }
            dbg("[Session] hasValidSession() → stored_ip={} player_ip={}", stored.get(), ip);
            if (!config.getSecurity().sessionIpBinding()) {
                dbg("[Session] hasValidSession() → ip-binding OFF → VALID");
                return true;
            }
            boolean match = stored.get().equals(ip);
            dbg("[Session] hasValidSession() → ip match={} → {}", match, match ? "VALID" : "INVALID");
            return match;
        } catch (DatabaseException e) {
            log.warn("[Session] Failed to check session for {} ({}): {}", uuid, ip, e.getMessage());
            return false;
        }
    }

    /**
     * Returns full session details for the self-service {@code /session}
     * command — see {@link SessionRepository.SessionInfo}. Unlike
     * {@link #hasValidSession}, this doesn't apply IP-binding logic; it just
     * reports whatever is on file so a player can see their own account's
     * trusted-session status (and notice an unfamiliar IP, if any).
     */
    public Optional<SessionRepository.SessionInfo> getSessionInfo(UUID uuid) {
        try {
            return repo.findSessionInfo(uuid);
        } catch (DatabaseException e) {
            log.warn("[Session] Failed to fetch session info for {}: {}", uuid, e.getMessage());
            return Optional.empty();
        }
    }

    // ── invalidate / clean ───────────────────────────────────────────────────

    /** Synchronously invalidates the session (logout or password change). */
    public void invalidate(UUID uuid) {
        dbg("[Session] invalidate() uuid={}", uuid);
        try {
            repo.delete(uuid);
        } catch (DatabaseException e) {
            log.warn("[Session] Failed to invalidate session for {}: {}", uuid, e.getMessage());
        }
    }

    /** Removes expired session rows. Returns count deleted. */
    public int cleanExpired() {
        try {
            int n = repo.deleteExpired();
            if (n > 0)
                log.info("[Session] Cleaned {} expired session(s).", n);
            return n;
        } catch (DatabaseException e) {
            log.warn("[Session] Failed to clean expired sessions: {}", e.getMessage());
            return 0;
        }
    }

    // ── helper ───────────────────────────────────────────────────────────────

    private void dbg(String fmt, Object... args) {
        if (debug != null)
            debug.log(fmt, args);
    }
}
