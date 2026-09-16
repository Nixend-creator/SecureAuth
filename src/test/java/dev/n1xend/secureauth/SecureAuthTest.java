package dev.n1xend.secureauth;

import dev.n1xend.secureauth.config.PluginConfig;
import dev.n1xend.secureauth.player.AuthState;
import dev.n1xend.secureauth.security.PasswordService;
import dev.n1xend.secureauth.util.CooldownManager;
import dev.n1xend.secureauth.util.RateLimiter;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SecureAuthTest {

    // ── AuthState ─────────────────────────────────────────────────────────────

    @Test
    void authState_defaultIsPending() {
        AuthState state = new AuthState();
        assertTrue(state.isPending());
        assertFalse(state.isAuthenticated());
        assertFalse(state.isAwaiting2Fa());
    }

    @Test
    void authState_transitions() {
        AuthState state = new AuthState();
        state.markAuthenticated();
        assertTrue(state.isAuthenticated());

        state.markAwaiting2Fa();
        assertTrue(state.isAwaiting2Fa());
        assertFalse(state.isAuthenticated());

        state.markPending();
        assertTrue(state.isPending());
    }

    @Test
    void authState_failureTracking() {
        AuthState state = new AuthState();
        assertEquals(0, state.getFailedAttempts());
        state.incrementFailures();
        state.incrementFailures();
        assertEquals(2, state.getFailedAttempts());
        state.resetFailures();
        assertEquals(0, state.getFailedAttempts());
    }

    // ── CooldownManager ──────────────────────────────────────────────────────

    @Test
    void cooldown_notActiveInitially() {
        CooldownManager cd = new CooldownManager(Duration.ofSeconds(30));
        UUID uuid = UUID.randomUUID();
        assertFalse(cd.isOnCooldown(uuid));
    }

    @Test
    void cooldown_activeAfterSet() {
        CooldownManager cd = new CooldownManager(Duration.ofSeconds(30));
        UUID uuid = UUID.randomUUID();
        cd.set(uuid);
        assertTrue(cd.isOnCooldown(uuid));
        assertTrue(cd.remainingSeconds(uuid) > 0);
        assertTrue(cd.remainingSeconds(uuid) <= 30);
    }

    @Test
    void cooldown_clearedAfterClear() {
        CooldownManager cd = new CooldownManager(Duration.ofSeconds(30));
        UUID uuid = UUID.randomUUID();
        cd.set(uuid);
        cd.clear(uuid);
        assertFalse(cd.isOnCooldown(uuid));
    }

    // ── RateLimiter ──────────────────────────────────────────────────────────

    @Test
    void rateLimiter_allowsUnderLimit() {
        RateLimiter rl = new RateLimiter(5, Duration.ofMinutes(1));
        UUID uuid = UUID.randomUUID();
        for (int i = 0; i < 5; i++) {
            assertTrue(rl.tryAcquire(uuid), "Attempt " + (i + 1) + " should be allowed");
        }
    }

    @Test
    void rateLimiter_blocksOverLimit() {
        RateLimiter rl = new RateLimiter(3, Duration.ofMinutes(1));
        UUID uuid = UUID.randomUUID();
        for (int i = 0; i < 3; i++)
            rl.tryAcquire(uuid);
        assertFalse(rl.tryAcquire(uuid), "4th attempt should be blocked");
    }

    @Test
    void rateLimiter_separateCountersPerPlayer() {
        RateLimiter rl = new RateLimiter(2, Duration.ofMinutes(1));
        UUID a = UUID.randomUUID();
        UUID b = UUID.randomUUID();

        rl.tryAcquire(a);
        rl.tryAcquire(a);
        assertFalse(rl.tryAcquire(a));
        assertTrue(rl.tryAcquire(b)); // b is independent
    }

    // ── PasswordService ──────────────────────────────────────────────────────

    @Test
    void password_hashAndVerify() {
        PluginConfig config = mock(PluginConfig.class);
        PluginConfig.SecurityConfig sc = new PluginConfig.SecurityConfig(65536, 3, 4, 5, 30, 30, true, 6, 64);
        when(config.getSecurity()).thenReturn(sc);

        PasswordService svc = new PasswordService(config);
        String hash = svc.hash("mySecurePassword123");
        assertNotNull(hash);
        assertTrue(svc.verify(hash, "mySecurePassword123"));
        assertFalse(svc.verify(hash, "wrongPassword"));
    }

    @Test
    void password_validationRejectsTooShort() {
        PluginConfig config = mock(PluginConfig.class);
        PluginConfig.SecurityConfig sc = new PluginConfig.SecurityConfig(65536, 3, 4, 5, 30, 30, true, 6, 64);
        when(config.getSecurity()).thenReturn(sc);

        PasswordService svc = new PasswordService(config);
        assertNotNull(svc.validate("abc")); // 3 chars < 6 min
        assertNull(svc.validate("validpassword")); // valid
    }
}
