package dev.n1xend.secureauth.player;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.n1xend.secureauth.database.DatabaseManager;
import dev.n1xend.secureauth.database.repository.PlayerRepository;
import dev.n1xend.secureauth.database.repository.RecoveryTokenRepository;
import dev.n1xend.secureauth.database.repository.EmailChangeRepository;
import org.slf4j.Logger;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Manages player lifecycle: load on pre-login, expose auth state, flush on quit.
 *
 * <p>Player data is cached in Caffeine. Auth state is held in a ConcurrentHashMap
 * (one entry per online player).
 *
 * <p>Design:
 * <ul>
 * <li>{@link #startLoading} — called in AsyncPlayerPreLoginEvent</li>
 * <li>{@link #awaitReady} — called in PlayerLoginEvent / PlayerJoinEvent</li>
 * <li>{@link #flush} — called in PlayerQuitEvent (sync)</li>
 * </ul>
 */
public final class PlayerDataService {

    private final PlayerRepository repo;
    private final RecoveryTokenRepository recoveryRepo;
    private final EmailChangeRepository emailChangeRepo;
    private final Logger log;

    /** Cache of player data (loaded from DB). Expire 10 min after write. */
    private final Cache<UUID, Optional<PlayerData>> dataCache = Caffeine.newBuilder().maximumSize(500)
            .expireAfterWrite(10, TimeUnit.MINUTES).build();

    /** In-flight loading futures (to avoid duplicate DB queries). */
    private final ConcurrentHashMap<UUID, CompletableFuture<Optional<PlayerData>>> loadingFutures = new ConcurrentHashMap<>();

    /** Live auth state per online player. */
    private final ConcurrentHashMap<UUID, AuthState> authStates = new ConcurrentHashMap<>();

    public PlayerDataService(DatabaseManager db, Logger log) {
        this.repo = new PlayerRepository(db);
        this.recoveryRepo = new RecoveryTokenRepository(db);
        this.emailChangeRepo = new EmailChangeRepository(db);
        this.log = log;
    }

    // ── Lifecycle ────────────────────────────────────────────────────────────

    /**
     * Called in AsyncPlayerPreLoginEvent — starts loading player data in background.
     */
    public CompletableFuture<Optional<PlayerData>> startLoading(UUID uuid) {
        CompletableFuture<Optional<PlayerData>> future = CompletableFuture.supplyAsync(() -> {
            Optional<PlayerData> cached = dataCache.getIfPresent(uuid);
            if (cached != null)
                return cached;
            Optional<PlayerData> data = repo.findByUuid(uuid);
            dataCache.put(uuid, data);
            return data;
        }, Thread::startVirtualThread);
        loadingFutures.put(uuid, future);
        return future;
    }

    /**
     * Called in PlayerLoginEvent — blocks up to {@code timeoutMs} for data to load.
     * Initialises the {@link AuthState} for this player.
     *
     * @return loaded {@link PlayerData} or empty
     */
    public Optional<PlayerData> awaitReady(UUID uuid, long timeoutMs) {
        Optional<PlayerData> result = Optional.empty();
        try {
            CompletableFuture<Optional<PlayerData>> f = loadingFutures.remove(uuid);
            if (f != null) {
                result = f.get(timeoutMs, TimeUnit.MILLISECONDS);
            } else {
                result = dataCache.getIfPresent(uuid);
                if (result == null)
                    result = Optional.empty();
            }
        } catch (Exception e) {
            log.warn("[PlayerData] awaitReady timeout/error for {}: {}", uuid, e.getMessage());
        }
        // Always initialise auth state on join
        authStates.put(uuid, new AuthState());
        return result;
    }

    /**
     * Called in PlayerQuitEvent — cleans up auth state.
     */
    public void flush(UUID uuid) {
        authStates.remove(uuid);
        // Keep data cache alive for quick re-join
    }

    // ── Auth state ───────────────────────────────────────────────────────────

    public AuthState getAuthState(UUID uuid) {
        return authStates.computeIfAbsent(uuid, k -> new AuthState());
    }

    public boolean isAuthenticated(UUID uuid) {
        AuthState s = authStates.get(uuid);
        return s != null && s.isAuthenticated();
    }

    // ── Data access ──────────────────────────────────────────────────────────

    /** Fetches player data, using cache. Async-safe. */
    public Optional<PlayerData> getData(UUID uuid) {
        Optional<PlayerData> cached = dataCache.getIfPresent(uuid);
        if (cached != null)
            return cached;
        Optional<PlayerData> data = repo.findByUuid(uuid);
        dataCache.put(uuid, data);
        return data;
    }

    /** Evicts and re-fetches player data (call after write operations). */
    public Optional<PlayerData> refreshData(UUID uuid) {
        dataCache.invalidate(uuid);
        return getData(uuid);
    }

    public void invalidate(UUID uuid) {
        dataCache.invalidate(uuid);
        loadingFutures.remove(uuid);
    }

    public PlayerRepository getRepository() {
        return repo;
    }

    public RecoveryTokenRepository getRecoveryRepository() {
        return recoveryRepo;
    }

    public EmailChangeRepository getEmailChangeRepository() {
        return emailChangeRepo;
    }

    /** Flushes all cached data (graceful shutdown). */
    public void flushAll() {
        authStates.clear();
        dataCache.invalidateAll();
        log.info("[PlayerData] All caches flushed.");
    }
}
