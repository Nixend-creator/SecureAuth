package dev.n1xend.secureauth.api;

import dev.n1xend.secureauth.antibot.AntiBotService;
import dev.n1xend.secureauth.api.impl.AntiBotApiImpl;
import dev.n1xend.secureauth.api.impl.SecureAuthApiImpl;
import dev.n1xend.secureauth.api.impl.SessionApiImpl;
import dev.n1xend.secureauth.api.impl.TotpApiImpl;
import dev.n1xend.secureauth.player.PlayerDataService;
import dev.n1xend.secureauth.session.SessionService;
import dev.n1xend.secureauth.twofa.TotpService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the SecureAuth public API layer.
 *
 * <p>All Bukkit-dependent code (forceAuthenticate / forceLogout / listeners)
 * requires a live server and is excluded here; covered by integration tests.
 */
class SecureAuthApiTest {

    private PlayerDataService playerData;
    private SessionService sessions;
    private TotpService totp;
    private AntiBotService antiBot;

    private SessionApiImpl sessionApi;
    private TotpApiImpl totpApi;
    private AntiBotApiImpl antiBotApi;

    @BeforeEach
    void setUp() {
        playerData = mock(PlayerDataService.class);
        sessions = mock(SessionService.class);
        totp = mock(TotpService.class);
        antiBot = mock(AntiBotService.class);

        sessionApi = new SessionApiImpl(sessions);
        totpApi = new TotpApiImpl(totp);
        antiBotApi = new AntiBotApiImpl(antiBot);
    }

    // ── SecureAuthApiImpl ─────────────────────────────────────────────────────

    @Test
    void apiImpl_versionForwarded() {
        SecureAuthApi api = buildApi("1.0.0-test");
        assertEquals("1.0.0-test", api.version());
    }

    @Test
    void apiImpl_subApisNotNull() {
        SecureAuthApi api = buildApi("1.0.0");
        assertNotNull(api.session());
        assertNotNull(api.totp());
        assertNotNull(api.antiBot());
    }

    // ── SessionApi ────────────────────────────────────────────────────────────

    @Test
    void session_hasValidSession_delegatesToService() {
        UUID uuid = UUID.randomUUID();
        when(sessions.hasValidSession(uuid, "1.2.3.4")).thenReturn(true);

        assertTrue(sessionApi.hasValidSession(uuid, "1.2.3.4"));
        verify(sessions).hasValidSession(uuid, "1.2.3.4");
    }

    @Test
    void session_createSession_delegatesToService() {
        UUID uuid = UUID.randomUUID();
        sessionApi.createSession(uuid, "1.2.3.4");
        verify(sessions).create(uuid, "1.2.3.4");
    }

    @Test
    void session_invalidateSession_delegatesToService() {
        UUID uuid = UUID.randomUUID();
        sessionApi.invalidateSession(uuid);
        verify(sessions).invalidate(uuid);
    }

    @Test
    void session_hasValidSessionAsync_delegatesToService() throws Exception {
        UUID uuid = UUID.randomUUID();
        when(sessions.hasValidSession(uuid, "1.2.3.4")).thenReturn(true);

        Boolean result = sessionApi.hasValidSessionAsync(uuid, "1.2.3.4").get(3, TimeUnit.SECONDS);
        assertTrue(result);
        verify(sessions).hasValidSession(uuid, "1.2.3.4");
    }

    @Test
    void session_createSessionAsync_delegatesToService() throws Exception {
        UUID uuid = UUID.randomUUID();
        sessionApi.createSessionAsync(uuid, "1.2.3.4").get(3, TimeUnit.SECONDS);
        verify(sessions).create(uuid, "1.2.3.4");
    }

    @Test
    void session_invalidateSessionAsync_delegatesToService() throws Exception {
        UUID uuid = UUID.randomUUID();
        sessionApi.invalidateSessionAsync(uuid).get(3, TimeUnit.SECONDS);
        verify(sessions).invalidate(uuid);
    }

    // ── TotpApi ───────────────────────────────────────────────────────────────

    @Test
    void totp_isEnabled_returnsCorrectFuture() throws Exception {
        UUID uuid = UUID.randomUUID();
        when(totp.isEnabled(uuid)).thenReturn(true);

        Boolean result = totpApi.isEnabled(uuid).get(3, TimeUnit.SECONDS);
        assertTrue(result);
        verify(totp).isEnabled(uuid);
    }

    @Test
    void totp_verify_returnsFalseForInvalidCode() throws Exception {
        UUID uuid = UUID.randomUUID();
        when(totp.verify(uuid, "000000")).thenReturn(false);

        Boolean result = totpApi.verify(uuid, "000000").get(3, TimeUnit.SECONDS);
        assertFalse(result);
    }

    @Test
    void totp_verify_returnsTrueForValidCode() throws Exception {
        UUID uuid = UUID.randomUUID();
        when(totp.verify(uuid, "123456")).thenReturn(true);

        Boolean result = totpApi.verify(uuid, "123456").get(3, TimeUnit.SECONDS);
        assertTrue(result);
    }

    // ── AntiBotApi ────────────────────────────────────────────────────────────

    @Test
    void antiBot_isBanned_delegatesToService() {
        when(antiBot.isBanned("10.0.0.1")).thenReturn(true);
        assertTrue(antiBotApi.isBanned("10.0.0.1"));
    }

    @Test
    void antiBot_banIp_delegatesToService() {
        LocalDateTime expiry = LocalDateTime.now().plusHours(1);
        antiBotApi.banIp("10.0.0.1", "test ban", expiry);
        verify(antiBot).banIp("10.0.0.1", "test ban", expiry);
    }

    @Test
    void antiBot_banIp_permanentBanAcceptsNullExpiry() {
        antiBotApi.banIp("10.0.0.1", "permanent", null);
        verify(antiBot).banIp("10.0.0.1", "permanent", null);
    }

    @Test
    void antiBot_unbanIp_delegatesToService() {
        antiBotApi.unbanIp("10.0.0.1");
        verify(antiBot).unbanIp("10.0.0.1");
    }

    @Test
    void antiBot_isBannedAsync_delegatesToService() throws Exception {
        when(antiBot.isBanned("10.0.0.1")).thenReturn(true);
        Boolean result = antiBotApi.isBannedAsync("10.0.0.1").get(3, TimeUnit.SECONDS);
        assertTrue(result);
        verify(antiBot).isBanned("10.0.0.1");
    }

    @Test
    void antiBot_banIpAsync_delegatesToService() throws Exception {
        LocalDateTime expiry = LocalDateTime.now().plusHours(1);
        antiBotApi.banIpAsync("10.0.0.1", "test ban", expiry).get(3, TimeUnit.SECONDS);
        verify(antiBot).banIp("10.0.0.1", "test ban", expiry);
    }

    @Test
    void antiBot_unbanIpAsync_delegatesToService() throws Exception {
        antiBotApi.unbanIpAsync("10.0.0.1").get(3, TimeUnit.SECONDS);
        verify(antiBot).unbanIp("10.0.0.1");
    }

    @Test
    void antiBot_getPendingLogins_delegatesToService() {
        when(antiBot.getPendingLogins()).thenReturn(7);
        assertEquals(7, antiBotApi.getPendingLogins());
    }

    // ── AuthApi.AuthSnapshot ──────────────────────────────────────────────────

    @Test
    void authSnapshot_authenticatedStageReportsTrue() {
        UUID uuid = UUID.randomUUID();
        AuthApi.AuthSnapshot snap = new AuthApi.AuthSnapshot(uuid, AuthApi.Stage.AUTHENTICATED, 0,
                System.currentTimeMillis());
        assertTrue(snap.authenticated());
    }

    @Test
    void authSnapshot_pendingStageReportsFalse() {
        UUID uuid = UUID.randomUUID();
        AuthApi.AuthSnapshot snap = new AuthApi.AuthSnapshot(uuid, AuthApi.Stage.PENDING, 2,
                System.currentTimeMillis());
        assertFalse(snap.authenticated());
    }

    @Test
    void authSnapshot_recordFieldsAccessible() {
        UUID uuid = UUID.randomUUID();
        long now = System.currentTimeMillis();
        AuthApi.AuthSnapshot snap = new AuthApi.AuthSnapshot(uuid, AuthApi.Stage.AWAITING_2FA, 3, now);

        assertEquals(uuid, snap.uuid());
        assertEquals(AuthApi.Stage.AWAITING_2FA, snap.stage());
        assertEquals(3, snap.failedAttempts());
        assertEquals(now, snap.joinedAt());
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private SecureAuthApi buildApi(String version) {
        return new SecureAuthApiImpl(version, mock(AuthApi.class), sessionApi, totpApi, antiBotApi);
    }
}
