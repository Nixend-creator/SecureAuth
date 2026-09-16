package dev.n1xend.secureauth.listener;

import dev.n1xend.secureauth.SecureAuthPlugin;
import dev.n1xend.secureauth.antibot.AntiBotService;
import dev.n1xend.secureauth.audit.AuditEvent;
import dev.n1xend.secureauth.config.PluginConfig;
import dev.n1xend.secureauth.geoip.GeoIpService;
import dev.n1xend.secureauth.i18n.LanguageManager;
import dev.n1xend.secureauth.player.AuthState;
import dev.n1xend.secureauth.player.PlayerData;
import dev.n1xend.secureauth.player.PlayerDataService;
import dev.n1xend.secureauth.session.SessionService;
import dev.n1xend.secureauth.webhook.WebhookService;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.*;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;
import org.bukkit.scheduler.BukkitRunnable;

import java.util.Optional;
import java.util.UUID;

/**
 * Handles player connect/disconnect lifecycle and applies auth restrictions.
 */
public final class AuthListener implements Listener {

    private final SecureAuthPlugin plugin;
    private final LanguageManager lang;
    private final PluginConfig config;
    private final PlayerDataService playerData;
    private final SessionService sessions;
    private final AntiBotService antiBot;
    private final GeoIpService geoIp;

    public AuthListener(SecureAuthPlugin plugin, LanguageManager lang, PluginConfig config,
            PlayerDataService playerData, SessionService sessions, AntiBotService antiBot, GeoIpService geoIp) {
        this.plugin = plugin;
        this.lang = lang;
        this.config = config;
        this.playerData = playerData;
        this.sessions = sessions;
        this.antiBot = antiBot;
        this.geoIp = geoIp;
    }

    // ── Pre-login — async, starts loading player data ───────────────────────

    @EventHandler(priority = EventPriority.HIGH)
    public void onAsyncPreLogin(AsyncPlayerPreLoginEvent event) {
        String ip = dev.n1xend.secureauth.util.IpUtil.normalize(event.getAddress().getHostAddress());
        UUID uuid = event.getPlayerProfile().getId();

        // AntiBot connection gate
        if (!antiBot.onConnection(uuid, ip)) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_BANNED, lang.buildKick("antibot.ip-blocked"));
            return;
        }

        // GeoIP check
        if (!geoIp.isAllowed(ip)) {
            String country = geoIp.getCountryCode(ip).orElse("Unknown");
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    lang.buildKick("kick.geoip-blocked", "country", country));
            antiBot.onPlayerLeave(uuid); // wasn't allowed in
            return;
        }

        // Start loading player data in background (fires before PlayerLoginEvent)
        playerData.startLoading(uuid);
    }

    /**
     * Safety net for {@link AntiBotService#getPendingLogins() pendingLogins}.
     *
     * <p>Our own {@code onAsyncPreLogin} above (HIGH priority) already
     * decrements explicitly when IT disallows a connection after counting it
     * (the GeoIP block case). But if a co-installed THIRD-PARTY plugin
     * (whitelist, another anti-bot, an unrelated ban plugin, etc.) disallows
     * the same {@link AsyncPlayerPreLoginEvent} at a priority after ours, that
     * connection never becomes a real {@code Player} and {@code PlayerQuitEvent}
     * — where the normal case is decremented, see {@code onPlayerQuit} — will
     * never fire for it. Without this, {@code pendingLogins} would leak
     * upward by one for every such rejection, eventually and permanently
     * hitting {@code max-pending-logins} and refusing every future connection
     * even with zero players online — a severe, entirely self-inflicted
     * denial of service that would only worsen over the server's uptime.
     *
     * <p>Registered at MONITOR (last) priority specifically to see the FINAL
     * verdict after every other plugin has had a chance to disallow the
     * event. {@link AntiBotService#onPlayerLeave} only decrements if this
     * specific {@code uuid} was actually counted by a prior
     * {@link AntiBotService#onConnection}, so calling it unconditionally here
     * — including for connections our OWN ban/flood check already rejected
     * before ever incrementing, or ones we already decremented explicitly
     * above for the GeoIP case — is always a safe no-op rather than an
     * incorrect extra decrement that would under-count real pending logins
     * during a genuine flood.
     */
    @EventHandler(priority = EventPriority.MONITOR)
    public void onAsyncPreLoginFinalCheck(AsyncPlayerPreLoginEvent event) {
        if (event.getLoginResult() != AsyncPlayerPreLoginEvent.Result.ALLOWED) {
            antiBot.onPlayerLeave(event.getPlayerProfile().getId());
        }
    }

    // ── Login — awaits data only; session check is deferred to onPlayerJoin ───
    //
    // Infinity-Filter (and similar reverse-proxy plugins) replace
    // player.getAddress() with the real client IP only AFTER PlayerLoginEvent.
    // getRealAddress() at this stage still returns the proxy IP.  We therefore
    // only pre-load player data here and perform the session check in
    // onPlayerJoin (MONITOR) where player.getAddress() is already the real IP.

    @EventHandler(priority = EventPriority.HIGH)
    public void onPlayerLogin(PlayerLoginEvent event) {
        Player player = event.getPlayer();
        UUID uuid = player.getUniqueId();

        plugin.getDebugLogger().log("[Login] onPlayerLogin uuid={} raw_ip={}", uuid,
                event.getRealAddress().getHostAddress());

        // Pre-load player data so it is ready by the time onPlayerJoin fires.
        playerData.awaitReady(uuid, 5000);
        // Initialise loginIp with whatever we have now; it will be overwritten
        // in onPlayerJoin once the proxy plugin has injected the real address.
        String ip = dev.n1xend.secureauth.util.IpUtil.normalize(event.getRealAddress().getHostAddress());
        playerData.getAuthState(uuid).setLoginIp(ip);
    }

    // ── Join — session check + visual restrictions ──────────────────────────
    //
    // MONITOR priority fires after all other plugins (including Infinity-Filter)
    // have processed PlayerJoinEvent.  By this point player.getAddress() already
    // contains the real client IP injected by the proxy plugin, so we can
    // perform a reliable session check here.
    //
    // ASYNC REFACTOR (2026-04): the ban/GeoIP/session checks below used to run
    // synchronously on the main thread right here — three blocking calls
    // (an IP-ban cache miss, a MaxMind file lookup, and a JDBC round-trip for
    // the session check) all inside a Bukkit event handler. This is exactly
    // the "must never block the main thread" rule this project enforces
    // everywhere else in the codebase; this method was the one deliberately
    // left alone for a long time because it had already broken repeatedly
    // across several earlier fixes (session persistence, IP handling,
    // blindness timing) and touching it again risked yet another regression.
    //
    // The fix that makes this safe: the ACTUAL security boundary here is
    // ProtectionListener checking AuthState.isAuthenticated() — not the
    // blindness effect, which is purely cosmetic feedback. AuthState defaults
    // to PENDING (not authenticated) the moment it's created, so a player is
    // already fully restricted (can't move, chat, or run commands) from the
    // instant they join, regardless of when — or whether — blindness gets
    // applied. That means the ban/GeoIP/session decision can safely be made
    // on a virtual thread without leaving any real security gap open in the
    // meantime; nothing more than a few-millisecond delay before the
    // cosmetic blindness effect (or a kick, or session restoration) actually
    // lands.
    //
    // Trade-off worth knowing about: a third-party plugin that reads
    // AuthApi.isAuthenticated() synchronously from its OWN PlayerJoinEvent
    // handler (at any priority, since ours no longer decides within the same
    // event dispatch) may observe "not yet authenticated" for a session that
    // is about to be restored a moment later. Before this change the
    // decision was already final by the time PlayerJoinEvent finished
    // processing; now it lands shortly after. Given the alternative was
    // blocking the main server thread on every single join, this is judged
    // the right trade to make — but it's a real behavior change for any
    // integration relying on synchronous availability during PlayerJoinEvent.
    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        UUID uuid = player.getUniqueId();
        AuthState state = playerData.getAuthState(uuid);

        // Re-read the IP now that proxy plugins have had a chance to inject it.
        // IpUtil.normalize() unwraps IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
        // so the stored and checked values are always in the same format.
        String realIp = dev.n1xend.secureauth.util.IpUtil.normalize(
                player.getAddress() != null ? player.getAddress().getAddress().getHostAddress() : state.getLoginIp());
        state.setLoginIp(realIp);
        plugin.getDebugLogger().log("[Join] onPlayerJoin uuid={} realIp={}", uuid, realIp);

        Thread.startVirtualThread(() -> {
            // ── Everything in this block is blocking I/O, now safely off the main thread ──

            boolean banned = plugin.getAntiBotService() != null && plugin.getAntiBotService().isBanned(realIp);
            boolean geoBlocked = false;
            String geoCountry = null;
            if (!banned && geoIp.isEnabled() && !geoIp.isAllowed(realIp)) {
                geoBlocked = true;
                geoCountry = geoIp.getCountryCode(realIp).orElse("Unknown");
            }

            boolean validSession = false;
            if (!banned && !geoBlocked) {
                Optional<PlayerData> data = playerData.getData(uuid);
                validSession = data.isPresent() && sessions.hasValidSession(uuid, realIp);
            }

            boolean finalBanned = banned;
            boolean finalGeoBlocked = geoBlocked;
            String finalGeoCountry = geoCountry;
            boolean finalValidSession = validSession;

            // ── Jump back to the main thread to act on the decision ──
            plugin.getMainThreadExecutor().execute(() -> {
                // The player may have disconnected while we were checking —
                // never act on a decision for someone who's already gone.
                if (!player.isOnline())
                    return;

                // SECOND enforcement layer for IP ban / GeoIP.
                //
                // Behind a reverse-proxy plugin such as Infinity-Filter, the real client
                // IP is only injected into player.getAddress() by the time PlayerJoinEvent
                // fires — AsyncPlayerPreLoginEvent still sees the proxy's own IP. This
                // means the pre-login ban/GeoIP gate in onAsyncPreLogin effectively checks
                // the PROXY's address, not the connecting player's — an attacker whose
                // real IP is banned would sail through that first gate every time.
                // We therefore re-check both here, against the now-correct real IP, and
                // kick immediately if either fails. This closes the bypass without
                // requiring Infinity-Filter's Proxy Protocol mode (which would make the
                // real IP available from the very first packet instead).
                if (finalBanned) {
                    plugin.getDebugLogger().log("[Join] Real IP {} is banned — kicking {}", realIp, player.getName());
                    player.kick(lang.buildKick("antibot.ip-blocked"));
                    return;
                }
                if (finalGeoBlocked) {
                    plugin.getDebugLogger().log("[Join] Real IP {} blocked by GeoIP ({}) — kicking {}", realIp,
                            finalGeoCountry, player.getName());
                    player.kick(lang.buildKick("kick.geoip-blocked", "country", finalGeoCountry));
                    return;
                }

                plugin.getDebugLogger().log("[Join] validSession={} for uuid={}", finalValidSession, uuid);

                if (finalValidSession) {
                    state.markAuthenticated();
                    sessions.createAsync(uuid, realIp);
                    plugin.getDebugLogger().log("[Join] Session restored for {}", player.getName());
                    lang.send(player, "login.session-restored", "player", player.getName());
                    if (plugin.getAuditLogService() != null) {
                        plugin.getAuditLogService().logAsync(AuditEvent.SESSION_RESTORE, uuid, player.getName(),
                                realIp);
                    }
                    Thread.startVirtualThread(() -> {
                        var ws = plugin.getWebhookService();
                        if (ws != null)
                            ws.fireAsync(WebhookService.Event.SESSION_RESTORE, player.getName(), uuid, realIp);
                    });
                    // SOFT ENFORCEMENT of two-factor.require-for-permission (see the matching
                    // comment in AuthCommand's /login handler for why this is soft, not a
                    // hard block). totp.isEnabled() is a blocking DB call, so it's pushed
                    // onto its own virtual thread since it's purely informational and never
                    // gates whether the player can act.
                    String requiredPerm = config.getTwoFa().requireForPermission();
                    if (!requiredPerm.isBlank() && player.hasPermission(requiredPerm)) {
                        Thread.startVirtualThread(() -> {
                            boolean has2fa = plugin.getTotpService().isEnabled(uuid);
                            if (!has2fa) {
                                plugin.getMainThreadExecutor()
                                        .execute(() -> lang.send(player, "twofa.required-reminder"));
                            }
                        });
                    }
                    return;
                }

                // Apply pre-auth restrictions
                if (config.getAuth().blindBeforeAuth()) {
                    player.addPotionEffect(new PotionEffect(PotionEffectType.BLINDNESS, 999999, 0, false, false));
                }

                // Show login/register prompt. playerData.getData() reads from the
                // in-memory cache populated by awaitReady() in onPlayerLogin — by this
                // point it's always already loaded, so this call is not blocking.
                if (playerData.getData(uuid).isEmpty()) {
                    lang.send(player, "login.require-register");
                } else {
                    lang.send(player, "login.require-auth");
                }

                // Schedule timeout kick — started from here (once we know the player
                // actually needs to log in) rather than from the original join instant;
                // the gap between the two is at most the time the checks above took.
                int timeoutSecs = config.getAuth().loginTimeoutSeconds();
                new BukkitRunnable() {
                    @Override
                    public void run() {
                        if (!player.isOnline())
                            return;
                        if (playerData.isAuthenticated(uuid))
                            return;
                        player.kick(lang.buildKick("kick.login-timeout", "seconds", String.valueOf(timeoutSecs)));
                    }
                }.runTaskLater(plugin, timeoutSecs * 20L);
            });
        });
    }

    // ── Quit — flush state, update antibot counter ──────────────────────────

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerQuit(PlayerQuitEvent event) {
        Player player = event.getPlayer();
        UUID uuid = player.getUniqueId();
        // Use the IP stored in AuthState (from getRealAddress at login) — same source
        // used when writing the session row, so audit log IPs are consistent.
        String ip = playerData.getAuthState(uuid).getLoginIp();

        // If the player was authenticated and didn't use /logout — fire DISCONNECT
        if (playerData.isAuthenticated(uuid)) {
            if (plugin.getAuditLogService() != null) {
                plugin.getAuditLogService().logAsync(AuditEvent.LOGOUT, uuid, player.getName(), ip);
            }
            Thread.startVirtualThread(() -> {
                var ws = plugin.getWebhookService();
                if (ws != null)
                    ws.fireAsync(WebhookService.Event.DISCONNECT, player.getName(), uuid, ip);
            });
        }

        playerData.flush(uuid);
        antiBot.onPlayerLeave(uuid);
    }
    // Note: PlayerKickEvent always fires PlayerQuitEvent in Paper,
    // so no separate handler needed — onPlayerQuit handles all cleanups.
}
