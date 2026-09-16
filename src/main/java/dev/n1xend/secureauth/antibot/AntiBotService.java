package dev.n1xend.secureauth.antibot;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.n1xend.secureauth.config.PluginConfig;
import dev.n1xend.secureauth.database.DatabaseManager;
import dev.n1xend.secureauth.database.repository.IpBanRepository;
import org.slf4j.Logger;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Protects against connection floods and brute-force attacks.
 *
 *
 * Tracks:
 * <ul>
 * <li>Connection rate per IP (per second window)</li>
 * <li>Number of pending (unauthenticated) logins</li>
 * <li>Failed login attempts per IP (triggers ban)</li>
 * </ul>
 */
public final class AntiBotService {

    private final PluginConfig config;
    private final Logger log;
    private IpBanRepository banRepo;

    /** Connection counter per IP — resets after 1 second. */
    private final Cache<String, AtomicInteger> connectionRate = Caffeine.newBuilder()
            .expireAfterWrite(1, TimeUnit.SECONDS).build();

    /** Failed attempt counter per IP in the current window. */
    private final Cache<String, AtomicInteger> failedPerIp = Caffeine.newBuilder()
            .expireAfterWrite(30, TimeUnit.MINUTES).build();

    /** Currently pending (not yet authenticated) player count. */
    private final AtomicInteger pendingLogins = new AtomicInteger(0);

    /**
     * UUIDs currently counted in {@link #pendingLogins}. Lets
     * {@link #onPlayerLeave} decrement only for connections we actually
     * incremented for — without this, a safety-net decrement fired for a
     * connection that was rejected BEFORE ever being counted (e.g. our own
     * ban/flood check failing) would silently under-count real pending
     * logins during a genuine flood, weakening the very ceiling this class
     * exists to enforce.
     *
     * <p>Backed by a Caffeine cache with a 10-minute TTL rather than a plain
     * Set: every currently-known disconnect path already calls
     * {@link #onPlayerLeave} explicitly (see {@code AuthListener}), but a TTL
     * bounds the damage from any disconnect path not yet accounted for —
     * without it, a single missed case would grow this set (and therefore
     * leak memory) forever, the same class of bug this whole fix exists to
     * close for {@link #pendingLogins} itself.
     */
    private final Cache<UUID, Boolean> countedPending = Caffeine.newBuilder().expireAfterWrite(10, TimeUnit.MINUTES)
            .build();

    /** In-memory ban cache (mirrors DB for fast reads). */
    private final Cache<String, Boolean> banCache = Caffeine.newBuilder().maximumSize(10_000)
            .expireAfterWrite(5, TimeUnit.MINUTES).build();

    public AntiBotService(PluginConfig config, Logger log) {
        this.config = config;
        this.log = log;
    }

    public void setDatabase(DatabaseManager db) {
        this.banRepo = new IpBanRepository(db);
    }

    // ── Connection gate ──────────────────────────────────────────────────────

    /**
     * Called when a connection arrives. Returns {@code true} if the connection should be allowed.
     *
     * @param uuid connecting player's UUID — used only to track whether this
     *             specific connection was counted toward {@link #pendingLogins},
     *             so {@link #onPlayerLeave} can decrement precisely.
     */
    public boolean onConnection(UUID uuid, String ip) {
        if (!config.getAntiBot().enabled())
            return true;

        // Check in-memory ban cache first
        Boolean banned = banCache.getIfPresent(ip);
        if (Boolean.TRUE.equals(banned))
            return false;

        // Check DB ban
        if (banRepo != null && banRepo.isBanned(ip)) {
            banCache.put(ip, true);
            return false;
        }

        // Check connection rate
        int rate = connectionRate.get(ip, k -> new AtomicInteger(0)).incrementAndGet();
        if (rate > config.getAntiBot().maxConnectionsPerSecond()) {
            log.warn("[AntiBot] Connection flood from IP: {} ({}/s)", ip, rate);
            return false;
        }

        // Check pending login ceiling
        if (pendingLogins.get() >= config.getAntiBot().maxPendingLogins()) {
            log.warn("[AntiBot] Max pending logins reached ({})", pendingLogins.get());
            return false;
        }

        pendingLogins.incrementAndGet();
        countedPending.put(uuid, Boolean.TRUE);
        return true;
    }

    /**
     * Called when a player completes authentication, disconnects, or a
     * previously-counted connection ends up disallowed by any means (e.g. a
     * co-installed third-party plugin rejecting the same
     * {@code AsyncPlayerPreLoginEvent} after ours already counted it).
     *
     * <p>Decrements {@link #pendingLogins} only if {@code uuid} was actually
     * counted by a prior {@link #onConnection} call — calling this for a
     * connection we never counted (e.g. one our own ban/flood check already
     * rejected before incrementing) is a safe, silent no-op rather than an
     * incorrect extra decrement.
     */
    public void onPlayerLeave(UUID uuid) {
        if (countedPending.getIfPresent(uuid) == null)
            return;
        countedPending.invalidate(uuid);
        pendingLogins.decrementAndGet();
        if (pendingLogins.get() < 0)
            pendingLogins.set(0);
    }

    // ── Failed attempt tracking ──────────────────────────────────────────────

    /**
     * Records a failed login attempt for an IP.
     * Bans the IP if threshold exceeded.
     */
    public void recordFailedAttempt(String ip) {
        int count = failedPerIp.get(ip, k -> new AtomicInteger(0)).incrementAndGet();
        if (count >= config.getAntiBot().ipBlockThreshold()) {
            banIp(ip, "Automatic block: " + count + " failed attempts",
                    LocalDateTime.now().plusMinutes(config.getAntiBot().ipBlockDurationMinutes()));
            log.warn("[AntiBot] Auto-banned IP {} after {} failed attempts", ip, count);
        }
    }

    public void clearFailures(String ip) {
        failedPerIp.invalidate(ip);
    }

    // ── IP bans ──────────────────────────────────────────────────────────────

    public void banIp(String ip, String reason, LocalDateTime expiresAt) {
        banCache.put(ip, true);
        if (banRepo != null) {
            banRepo.ban(ip, reason, expiresAt);
        }
    }

    public void unbanIp(String ip) {
        banCache.invalidate(ip);
        if (banRepo != null) {
            banRepo.unban(ip);
        }
    }

    public boolean isBanned(String ip) {
        Boolean cached = banCache.getIfPresent(ip);
        if (cached != null)
            return cached;
        if (banRepo == null)
            return false;
        boolean banned = banRepo.isBanned(ip);
        banCache.put(ip, banned);
        return banned;
    }

    public int getPendingLogins() {
        return pendingLogins.get();
    }
}
