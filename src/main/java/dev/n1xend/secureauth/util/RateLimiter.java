package dev.n1xend.secureauth.util;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Sliding-window rate limiter per player.
 *
 * <p>Usage: max N attempts within a time window.
 */
public final class RateLimiter {

    private final int maxAttempts;
    private final Cache<UUID, AtomicInteger> counters;

    public RateLimiter(int maxAttempts, Duration window) {
        this.maxAttempts = maxAttempts;
        this.counters = Caffeine.newBuilder().expireAfterWrite(window).build();
    }

    /**
     * Attempts to acquire a permit.
     *
     * @return {@code true} if allowed (under limit), {@code false} if rate-limited
     */
    public boolean tryAcquire(UUID uuid) {
        int count = counters.get(uuid, k -> new AtomicInteger(0)).incrementAndGet();
        return count <= maxAttempts;
    }

    public void reset(UUID uuid) {
        counters.invalidate(uuid);
    }
}
