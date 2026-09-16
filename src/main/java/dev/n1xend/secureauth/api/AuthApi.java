package dev.n1xend.secureauth.api;

import org.jetbrains.annotations.NotNull;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * API for querying and controlling per-player authentication state.
 *
 * <p>All methods are thread-safe. Methods that touch the database return
 * {@link CompletableFuture} and execute on virtual threads — never block
 * the main thread waiting for them.
 */
public interface AuthApi {

    /**
     * Returns whether a player is currently fully authenticated.
     *
     * <p>Returns {@code false} for offline players.
     *
     * @param uuid player UUID
     * @return {@code true} if authenticated
     */
    boolean isAuthenticated(@NotNull UUID uuid);

    /**
     * Returns whether a player is registered (has a password hash in the database).
     *
     * <p>Uses Caffeine cache — safe to call frequently.
     *
     * @param uuid player UUID
     * @return future resolving to {@code true} if registered
     */
    @NotNull
    CompletableFuture<Boolean> isRegistered(@NotNull UUID uuid);

    /**
     * Returns a read-only snapshot of authentication status for a player.
     *
     * <p>Returns {@link Optional#empty()} for offline or unregistered players.
     *
     * @param uuid player UUID
     * @return optional snapshot
     */
    @NotNull
    Optional<AuthSnapshot> getSnapshot(@NotNull UUID uuid);

    /**
     * Force-authenticates a player, skipping password / 2FA checks.
     *
     * <p>Must be called on the main thread. Intended for admin tools,
     * adventure maps, or mini-game integrations that manage auth externally.
     *
     * @param uuid player UUID — must be online
     * @throws IllegalArgumentException if the player is not online
     */
    void forceAuthenticate(@NotNull UUID uuid);

    /**
     * Force-deauthenticates (logs out) a player.
     *
     * <p>Must be called on the main thread.
     *
     * @param uuid player UUID — must be online
     */
    void forceLogout(@NotNull UUID uuid);

    /**
     * Registers a listener that is notified when a player's auth state changes.
     *
     * <p>The listener is called on the main thread after the state transition.
     *
     * @param listener listener to add
     */
    void addAuthListener(@NotNull AuthStateListener listener);

    /**
     * Removes a previously added listener.
     *
     * @param listener listener to remove
     */
    void removeAuthListener(@NotNull AuthStateListener listener);

    // ── Inner types ───────────────────────────────────────────────────────────

    /**
     * Immutable snapshot of a player's authentication state at a point in time.
     *
     * @param uuid           player UUID
     * @param stage          current auth stage
     * @param failedAttempts number of failed login attempts in this session
     * @param joinedAt       epoch millis when the player joined
     */
    record AuthSnapshot(@NotNull UUID uuid, @NotNull Stage stage, int failedAttempts, long joinedAt) {

        /** Returns {@code true} if the player is fully authenticated. */
        public boolean authenticated() {
            return stage == Stage.AUTHENTICATED;
        }
    }

    /**
     * Authentication stages, mirroring the internal {@code AuthState.Stage}.
     */
    enum Stage {
        /** Player has not yet submitted /login or /register. */
        PENDING,
        /** Password verified, waiting for /2fa code. */
        AWAITING_2FA,
        /** Fully authenticated. */
        AUTHENTICATED
    }

    /**
     * Callback fired when a player's authentication stage changes.
     */
    @FunctionalInterface
    interface AuthStateListener {

        /**
         * Called after the transition completes on the main thread.
         *
         * @param uuid     player UUID
         * @param previous stage before the change
         * @param current  stage after the change
         */
        void onAuthStateChanged(@NotNull UUID uuid, @NotNull Stage previous, @NotNull Stage current);
    }
}
