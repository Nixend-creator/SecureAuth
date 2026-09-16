package dev.n1xend.secureauth.api;

import org.jetbrains.annotations.NotNull;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * API for querying TOTP (Time-based One-Time Password) two-factor authentication status.
 *
 * <p>All database-backed methods return {@link CompletableFuture} and execute on
 * virtual threads. Never block the main thread waiting for them.
 */
public interface TotpApi {

    /**
     * Returns whether TOTP 2FA is enabled for the given player.
     *
     * <p>Performs a database read — always returns a future.
     * Uses virtual threads internally; safe to call from any thread.
     *
     * @param uuid player UUID
     * @return future resolving to {@code true} if 2FA is enabled
     */
    @NotNull
    CompletableFuture<Boolean> isEnabled(@NotNull UUID uuid);

    /**
     * Verifies a TOTP code or backup code for a player.
     *
     * <p>Backup codes are single-use and marked consumed on success.
     *
     * @param uuid player UUID
     * @param code 6-digit TOTP code, or backup code
     * @return future resolving to {@code true} if the code is valid
     */
    @NotNull
    CompletableFuture<Boolean> verify(@NotNull UUID uuid, @NotNull String code);
}
