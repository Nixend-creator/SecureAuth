package dev.n1xend.secureauth.papi;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.n1xend.secureauth.player.AuthState;
import dev.n1xend.secureauth.player.PlayerData;
import dev.n1xend.secureauth.player.PlayerDataService;
import dev.n1xend.secureauth.session.SessionService;
import dev.n1xend.secureauth.twofa.TotpService;
import me.clip.placeholderapi.expansion.PlaceholderExpansion;
import org.bukkit.OfflinePlayer;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * PlaceholderAPI expansion for SecureAuth.
 *
 * <p>Registered internally from {@link dev.n1xend.secureauth.SecureAuthPlugin#onEnable()}
 * only when PlaceholderAPI is present. Uses {@link #persist()} = true so the expansion
 * survives {@code /papi reload} without requiring a full server restart.
 *
 * <p><strong>Available placeholders:</strong>
 * <pre>
 * %secureauth_is_authenticated%   — true/false  (online only)
 * %secureauth_is_registered%      — true/false  (uses Caffeine cache)
 * %secureauth_auth_status%        — AUTHENTICATED / AWAITING_2FA / PENDING / OFFLINE
 * %secureauth_has_2fa%            — true/false
 * %secureauth_registered_at%      — ISO date string or N/A
 * %secureauth_last_login%         — ISO date string, "Never", or N/A
 * %secureauth_last_login_ip%      — masked IP (192.168.*.*) or N/A
 * %secureauth_has_session%        — true/false  (online only)
 * %secureauth_failed_attempts%    — integer count (online only)
 * </pre>
 */
public final class SecureAuthExpansion extends PlaceholderExpansion {

    private final PlayerDataService playerData;
    private final TotpService totp;
    private final SessionService sessions;

    // has_2fa and has_session are the only two placeholders here that hit the
    // database on every single call — unlike everything else in this class,
    // which reads from PlayerDataService's already-cached getData(). Some
    // scoreboard/tab-list/bossbar plugins poll every placeholder on every
    // online player once a second (or faster); without this cache that would
    // mean an unbounded rate of synchronous DB queries on the main thread —
    // exactly the kind of main-thread-blocking call this project has
    // repeatedly had to hunt down and fix elsewhere. A short 3s TTL keeps the
    // displayed value fresh enough for a UI element while capping query rate.
    private final Cache<UUID, Boolean> has2faCache = Caffeine.newBuilder().expireAfterWrite(3, TimeUnit.SECONDS)
            .maximumSize(2000).build();
    private final Cache<UUID, Boolean> hasSessionCache = Caffeine.newBuilder().expireAfterWrite(3, TimeUnit.SECONDS)
            .maximumSize(2000).build();

    public SecureAuthExpansion(PlayerDataService playerData, TotpService totp, SessionService sessions) {
        this.playerData = playerData;
        this.totp = totp;
        this.sessions = sessions;
    }

    // ── PlaceholderExpansion contract ─────────────────────────────────────────

    @Override
    public @NotNull String getIdentifier() {
        return "secureauth";
    }

    @Override
    public @NotNull String getAuthor() {
        return "Nixend-creator";
    }

    @Override
    public @NotNull String getVersion() {
        return "1.0.0";
    }

    /**
     * REQUIRED for internally-registered expansions.
     * Without this, PlaceholderAPI unregisters us on {@code /papi reload}.
     */
    @Override
    public boolean persist() {
        return true;
    }

    /**
     * No separate jar / eCloud entry — always registrable as long as the
     * SecureAuth services are live (checked in onEnable before calling register()).
     */
    @Override
    public boolean canRegister() {
        return true;
    }

    // ── Placeholder resolution ────────────────────────────────────────────────

    /**
     * Main entry point. {@code identifier} is the part after {@code secureauth_}.
     * Return {@code null} for unknown identifiers — PAPI will leave the placeholder raw.
     */
    @Override
    public @Nullable String onRequest(@Nullable OfflinePlayer player, @NotNull String identifier) {
        if (player == null)
            return "";

        return switch (identifier) {
            case "is_authenticated" -> resolveIsAuthenticated(player);
            case "is_registered" -> resolveIsRegistered(player);
            case "auth_status" -> resolveAuthStatus(player);
            case "has_2fa" -> resolveHas2Fa(player);
            case "registered_at" -> resolveRegisteredAt(player);
            case "last_login" -> resolveLastLogin(player);
            case "last_login_ip" -> resolveLastLoginIp(player);
            case "has_session" -> resolveHasSession(player);
            case "failed_attempts" -> resolveFailedAttempts(player);
            default -> null;
        };
    }

    // ── Resolvers ─────────────────────────────────────────────────────────────

    private String resolveIsAuthenticated(OfflinePlayer player) {
        if (!player.isOnline())
            return "false";
        return String.valueOf(playerData.isAuthenticated(player.getUniqueId()));
    }

    private String resolveIsRegistered(OfflinePlayer player) {
        Optional<PlayerData> data = playerData.getData(player.getUniqueId());
        return data.isPresent() ? "true" : "false";
    }

    private String resolveAuthStatus(OfflinePlayer player) {
        if (!player.isOnline())
            return "OFFLINE";
        AuthState state = playerData.getAuthState(player.getUniqueId());
        if (state == null)
            return "OFFLINE";
        return state.getStage().name(); // PENDING | AWAITING_2FA | AUTHENTICATED
    }

    private String resolveHas2Fa(OfflinePlayer player) {
        UUID uuid = player.getUniqueId();
        Boolean cached = has2faCache.getIfPresent(uuid);
        if (cached != null)
            return String.valueOf(cached);
        boolean enabled = totp.isEnabled(uuid);
        has2faCache.put(uuid, enabled);
        return String.valueOf(enabled);
    }

    private String resolveRegisteredAt(OfflinePlayer player) {
        return playerData.getData(player.getUniqueId()).map(d -> d.registeredAt() != null ? d.registeredAt() : "N/A")
                .orElse("N/A");
    }

    private String resolveLastLogin(OfflinePlayer player) {
        return playerData.getData(player.getUniqueId()).map(d -> d.lastLoginAt() != null ? d.lastLoginAt() : "Never")
                .orElse("N/A");
    }

    private String resolveLastLoginIp(OfflinePlayer player) {
        return playerData.getData(player.getUniqueId()).map(d -> maskIp(d.lastLoginIp())).orElse("N/A");
    }

    private String resolveHasSession(OfflinePlayer player) {
        if (!player.isOnline())
            return "false";
        var online = player.getPlayer();
        if (online == null || online.getAddress() == null)
            return "false";
        UUID uuid = player.getUniqueId();
        Boolean cached = hasSessionCache.getIfPresent(uuid);
        if (cached != null)
            return String.valueOf(cached);
        String ip = online.getAddress().getAddress().getHostAddress();
        boolean valid = sessions.hasValidSession(uuid, ip);
        hasSessionCache.put(uuid, valid);
        return String.valueOf(valid);
    }

    private String resolveFailedAttempts(OfflinePlayer player) {
        if (!player.isOnline())
            return "0";
        AuthState state = playerData.getAuthState(player.getUniqueId());
        if (state == null)
            return "0";
        return String.valueOf(state.getFailedAttempts());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Masks an IP for privacy.
     * IPv4: {@code 192.168.1.100} → {@code 192.168.*.*}
     * IPv6: {@code 2001:db8::1}   → {@code 2001:db8:****}
     */
    private static String maskIp(@Nullable String ip) {
        if (ip == null || ip.isBlank())
            return "N/A";
        String[] parts = ip.split("\\.");
        if (parts.length == 4) {
            return parts[0] + "." + parts[1] + ".*.*";
        }
        int colon = ip.lastIndexOf(':');
        if (colon > 0)
            return ip.substring(0, colon) + ":****";
        return "***";
    }
}
