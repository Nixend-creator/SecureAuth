package dev.n1xend.secureauth.api;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.time.LocalDateTime;
import java.util.concurrent.CompletableFuture;

/**
 * API for querying and managing IP bans enforced by SecureAuth's anti-bot system.
 *
 * <p>Ban state is backed by both an in-memory Caffeine cache and the
 * database.
 *
 * <p><strong>Threading:</strong> {@link #banIp} and {@link #unbanIp} always
 * perform a blocking JDBC write — do not call them from the main thread, use
 * {@link #banIpAsync}/{@link #unbanIpAsync} instead. {@link #isBanned} checks
 * the in-memory cache first and is usually fast, but a cache miss (e.g. an IP
 * that hasn't been checked recently, or right after a cache eviction) still
 * falls through to a blocking JDBC read — prefer {@link #isBannedAsync} for
 * main-thread callers unless you specifically know the IP was just checked.
 */
public interface AntiBotApi {

    /**
     * Returns whether the given IP address is currently banned.
     *
     * @param ip IPv4 or IPv6 address string
     * @return {@code true} if banned
     */
    boolean isBanned(@NotNull String ip);

    /** Async, non-blocking equivalent of {@link #isBanned}. Safe to call from the main thread. */
    @NotNull
    CompletableFuture<Boolean> isBannedAsync(@NotNull String ip);

    /**
     * Bans an IP address until the given expiry time.
     *
     * <p>Passing {@code null} for {@code expiresAt} creates a permanent ban.
     * The ban is persisted to the database and cached in memory.
     *
     * @param ip       IPv4 or IPv6 address string
     * @param reason   human-readable reason (shown in logs)
     * @param expiresAt expiry timestamp, or {@code null} for permanent
     */
    void banIp(@NotNull String ip, @NotNull String reason, @Nullable LocalDateTime expiresAt);

    /** Async, non-blocking equivalent of {@link #banIp}. Safe to call from the main thread. */
    @NotNull
    CompletableFuture<Void> banIpAsync(@NotNull String ip, @NotNull String reason, @Nullable LocalDateTime expiresAt);

    /**
     * Unbans an IP address.
     *
     * <p>Clears both the in-memory cache entry and the database record.
     *
     * @param ip IPv4 or IPv6 address string
     */
    void unbanIp(@NotNull String ip);

    /** Async, non-blocking equivalent of {@link #unbanIp}. Safe to call from the main thread. */
    @NotNull
    CompletableFuture<Void> unbanIpAsync(@NotNull String ip);

    /**
     * Returns the number of currently pending (unauthenticated) logins.
     *
     * <p>Backed by an in-memory counter only — never touches the database,
     * safe to call from the main thread.
     *
     * @return pending login count, &gt;= 0
     */
    int getPendingLogins();
}
