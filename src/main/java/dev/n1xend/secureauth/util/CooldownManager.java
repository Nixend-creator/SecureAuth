package dev.n1xend.secureauth.util;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Per-player cooldown manager backed by Caffeine.
 *
 * <p>Usage:
 * <pre>{@code
 * private final CooldownManager loginCooldown = new CooldownManager(Duration.ofSeconds(5));
 *
 * if (loginCooldown.isOnCooldown(uuid)) {
 *     lang.send(player, "login.cooldown", "seconds",
 *               String.valueOf(loginCooldown.remainingSeconds(uuid)));
 *     return;
 * }
 * loginCooldown.set(uuid);
 * }</pre>
 */
public final class CooldownManager {

    private final Duration duration;
    /** Stores the timestamp (ms) when the cooldown expires. */
    private final Cache<UUID, Long> cache;

    public CooldownManager(Duration duration) {
        this.duration = duration;
        this.cache = Caffeine.newBuilder().expireAfterWrite(duration.toMillis() + 1000, TimeUnit.MILLISECONDS).build();
    }

    public boolean isOnCooldown(UUID uuid) {
        Long expires = cache.getIfPresent(uuid);
        return expires != null && System.currentTimeMillis() < expires;
    }

    public long remainingSeconds(UUID uuid) {
        Long expires = cache.getIfPresent(uuid);
        if (expires == null)
            return 0;
        long remaining = (expires - System.currentTimeMillis()) / 1000;
        return Math.max(0, remaining);
    }

    public void set(UUID uuid) {
        cache.put(uuid, System.currentTimeMillis() + duration.toMillis());
    }

    public void clear(UUID uuid) {
        cache.invalidate(uuid);
    }
}
