package dev.n1xend.secureauth.api;

import org.jetbrains.annotations.NotNull;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * API for IP-based session management.
 *
 * <p>Sessions allow players to skip re-authentication on quick reconnects
 * from the same IP address.
 *
 * <p><strong>Threading:</strong> every method here performs a blocking JDBC
 * call under the hood. "Thread-safe" (no data races between callers) is
 * <em>not</em> the same guarantee as "non-blocking" — calling any of the
 * {@code *Session} methods directly from the main server thread (e.g. from
 * inside a Bukkit event handler, which is the most common integration
 * pattern) will stall that tick for the duration of the database round-trip.
 * Prefer the {@code *Async} overloads below when calling from the main
 * thread; they return a {@link CompletableFuture} completed on a background
 * virtual thread. The synchronous overloads remain available for callers
 * that are already off the main thread (e.g. inside their own async task or
 * virtual thread).
 */
public interface SessionApi {

    /**
     * Returns whether a valid (non-expired) session exists for this player and IP.
     *
     * <p>When IP-binding is disabled in config, the IP argument is ignored.
     *
     * <p><strong>Blocking:</strong> performs a synchronous JDBC query. Do not
     * call from the main thread — use {@link #hasValidSessionAsync} instead.
     *
     * @param uuid player UUID
     * @param ip   player's current IP address
     * @return {@code true} if the session is valid
     */
    boolean hasValidSession(@NotNull UUID uuid, @NotNull String ip);

    /** Async, non-blocking equivalent of {@link #hasValidSession}. Safe to call from the main thread. */
    @NotNull
    CompletableFuture<Boolean> hasValidSessionAsync(@NotNull UUID uuid, @NotNull String ip);

    /**
     * Creates or refreshes a session for the given player.
     *
     * <p>Session TTL is taken from {@code security.session-timeout-minutes} in config.
     *
     * <p><strong>Blocking:</strong> performs a synchronous JDBC write. Do not
     * call from the main thread — use {@link #createSessionAsync} instead.
     *
     * @param uuid player UUID
     * @param ip   player's current IP address
     */
    void createSession(@NotNull UUID uuid, @NotNull String ip);

    /** Async, non-blocking equivalent of {@link #createSession}. Safe to call from the main thread. */
    @NotNull
    CompletableFuture<Void> createSessionAsync(@NotNull UUID uuid, @NotNull String ip);

    /**
     * Invalidates the session for the given player (e.g. on logout or password change).
     *
     * <p><strong>Blocking:</strong> performs a synchronous JDBC write. Do not
     * call from the main thread — use {@link #invalidateSessionAsync} instead.
     *
     * @param uuid player UUID
     */
    void invalidateSession(@NotNull UUID uuid);

    /** Async, non-blocking equivalent of {@link #invalidateSession}. Safe to call from the main thread. */
    @NotNull
    CompletableFuture<Void> invalidateSessionAsync(@NotNull UUID uuid);
}
