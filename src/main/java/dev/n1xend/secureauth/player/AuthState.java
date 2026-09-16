package dev.n1xend.secureauth.player;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Mutable in-memory authentication state for an online player.
 * One instance per online player, stored in {@link PlayerDataService}.
 *
 * <p><strong>Thread safety:</strong> instances of this class are read and
 * written from both the main server thread (event handlers, command
 * dispatch) and virtual threads (password/2FA verification, DB writes) — the
 * whole point of offloading those checks off the main thread. A plain
 * {@code int}/enum field mutated on one thread has no guaranteed visibility
 * to a read on another thread under the Java Memory Model without
 * {@code volatile} or equivalent synchronization; without it, a state change
 * made on one thread could be invisible to a check running on another for an
 * unbounded amount of time, or never at all on some JIT-optimized paths.
 * {@code stage} and {@code loginIp} are therefore {@code volatile}, and
 * {@code failedAttempts} uses {@link AtomicInteger} so concurrent
 * {@code incrementFailures()} calls (e.g. two /login attempts submitted back
 * to back, both slipping past the cooldown check before either sets it) don't
 * lose an increment to a classic read-modify-write race.
 */
public final class AuthState {

    public enum Stage {
        /** Player has not yet submitted /login or /register */
        PENDING,
        /** Password verified, waiting for /2fa code */
        AWAITING_2FA,
        /** Fully authenticated */
        AUTHENTICATED
    }

    private volatile Stage stage = Stage.PENDING;
    private final AtomicInteger failedAttempts = new AtomicInteger(0);
    private final long joinedAt = System.currentTimeMillis();
    /** IP address from PlayerLoginEvent.getRealAddress() — single source of truth. */
    private volatile String loginIp = "unknown";

    // ── Stage transitions ────────────────────────────────────────────────────

    public void markAuthenticated() {
        this.stage = Stage.AUTHENTICATED;
    }

    public void markAwaiting2Fa() {
        this.stage = Stage.AWAITING_2FA;
    }

    public void markPending() {
        this.stage = Stage.PENDING;
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    public boolean isAuthenticated() {
        return stage == Stage.AUTHENTICATED;
    }

    public boolean isAwaiting2Fa() {
        return stage == Stage.AWAITING_2FA;
    }

    public boolean isPending() {
        return stage == Stage.PENDING;
    }

    public Stage getStage() {
        return stage;
    }

    public int getFailedAttempts() {
        return failedAttempts.get();
    }

    public void incrementFailures() {
        failedAttempts.incrementAndGet();
    }

    public void resetFailures() {
        failedAttempts.set(0);
    }

    public long getJoinedAt() {
        return joinedAt;
    }

    public String getLoginIp() {
        return loginIp;
    }

    public void setLoginIp(String ip) {
        this.loginIp = ip;
    }

    @Override
    public String toString() {
        return "AuthState{stage=" + stage + ", failed=" + failedAttempts.get() + "}";
    }
}
