package dev.n1xend.secureauth.command;

import dev.n1xend.secureauth.SecureAuthPlugin;
import dev.n1xend.secureauth.api.AuthApi;
import dev.n1xend.secureauth.config.PluginConfig;
import dev.n1xend.secureauth.email.EmailService;
import dev.n1xend.secureauth.i18n.LanguageManager;
import dev.n1xend.secureauth.player.AuthState;
import dev.n1xend.secureauth.player.PlayerData;
import dev.n1xend.secureauth.player.PlayerDataService;
import dev.n1xend.secureauth.security.PasswordService;
import dev.n1xend.secureauth.session.SessionService;
import dev.n1xend.secureauth.twofa.TotpService;
import dev.n1xend.secureauth.util.CooldownManager;
import dev.n1xend.secureauth.util.RateLimiter;
import dev.n1xend.secureauth.audit.AuditEvent;
import dev.n1xend.secureauth.webhook.WebhookService;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.potion.PotionEffectType;
import org.jetbrains.annotations.NotNull;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

/**
 * Registers and handles all player-facing auth commands.
 *
 * <p>Heavy work (password hashing/verification) runs on Virtual Threads.
 * Results are dispatched back to the main thread via {@code mainThreadExecutor}.
 */
public final class AuthCommand {

    private final SecureAuthPlugin plugin;
    private final LanguageManager lang;
    private final PluginConfig config;
    private final PlayerDataService playerData;
    private final PasswordService passwords;
    private final SessionService sessions;
    private final TotpService totp;
    private final EmailService email;

    private final CooldownManager loginCooldown = new CooldownManager(Duration.ofSeconds(5));
    private final CooldownManager registerCooldown = new CooldownManager(Duration.ofSeconds(10));
    // Applies to the SEND step of /recover and /setemail (not the confirm step,
    // which is separately rate-limited via recoveryRateLimit). Without this,
    // an authenticated player could spam /setemail <arbitrary-address> with no
    // limit, turning the server's SMTP account into an open mail-bomber against
    // any third-party inbox — this cooldown closes that gap.
    private final CooldownManager emailSendCooldown = new CooldownManager(Duration.ofSeconds(60));
    private final RateLimiter loginRateLimit;
    private final RateLimiter registerRateLimit;
    private final RateLimiter totpRateLimit;
    // Recovery-confirm attempts are rate-limited even though the token has
    // ~186 bits of entropy — defense in depth against any future weakening
    // of the token format, and consistent with every other verify path here.
    private final RateLimiter recoveryRateLimit = new RateLimiter(5, Duration.ofMinutes(15));

    public AuthCommand(SecureAuthPlugin plugin, LanguageManager lang, PluginConfig config, PlayerDataService playerData,
            PasswordService passwords, SessionService sessions, TotpService totp, EmailService email) {
        this.plugin = plugin;
        this.lang = lang;
        this.config = config;
        this.playerData = playerData;
        this.passwords = passwords;
        this.sessions = sessions;
        this.totp = totp;
        this.email = email;

        PluginConfig.RateLimitConfig rl = config.getRateLimit();
        loginRateLimit = new RateLimiter(rl.loginMax(), Duration.ofSeconds(rl.loginWindowSeconds()));
        registerRateLimit = new RateLimiter(rl.registerMax(), Duration.ofSeconds(rl.registerWindowSeconds()));
        totpRateLimit = new RateLimiter(rl.totpMax(), Duration.ofSeconds(rl.totpWindowSeconds()));
    }

    // ── Command builders ─────────────────────────────────────────────────────

    public Command registerLogin() {
        return new CommandBase("login", lang) {
            @Override
            public boolean execute(@NotNull CommandSender sender, @NotNull String label, @NotNull String[] args) {
                if (!requirePlayer(sender))
                    return true;
                Player player = (Player) sender;
                UUID uuid = player.getUniqueId();

                if (args.length < 1) {
                    lang.send(player, "login.usage");
                    return true;
                }

                if (loginCooldown.isOnCooldown(uuid) && !player.hasPermission("secureauth.cooldown.bypass")) {
                    lang.send(player, "login.cooldown", "seconds",
                            String.valueOf(loginCooldown.remainingSeconds(uuid)));
                    return true;
                }
                if (!loginRateLimit.tryAcquire(uuid)) {
                    lang.send(player, "login.rate-limited");
                    return true;
                }
                // SECURITY: set the cooldown here, synchronously, BEFORE handing off to
                // the virtual thread that does the (deliberately slow) Argon2 verify.
                // Setting it only after verification completes (as this used to do)
                // leaves a window the size of the hash computation time — often
                // 100-500ms depending on config — during which several more /login
                // commands can be accepted and each spawn their own concurrent
                // verification, bypassing the pacing the cooldown exists to provide.
                // loginRateLimit still independently caps the total attempt count
                // regardless of this timing, but the cooldown's actual job (spacing
                // guesses out in real time) only works if it's set immediately.
                loginCooldown.set(uuid);

                String password = args[0];

                Thread.startVirtualThread(() -> {
                    Optional<PlayerData> data = playerData.getData(uuid);
                    if (data.isEmpty()) {
                        plugin.getMainThreadExecutor().execute(() -> lang.send(player, "login.not-registered"));
                        return;
                    }
                    AuthState state = playerData.getAuthState(uuid);
                    if (state.isAuthenticated()) {
                        plugin.getMainThreadExecutor().execute(() -> lang.send(player, "login.already-logged-in"));
                        return;
                    }

                    // SECURITY: persistent, cross-session lockout check.
                    //
                    // AuthState (and its in-session failedAttempts counter, checked
                    // further below) is created fresh on every new connection —
                    // reconnecting resets it to zero. Without this check, an attacker
                    // could hit max-login-attempts, disconnect, immediately reconnect
                    // to a brand-new AuthState, and keep guessing indefinitely — the
                    // only thing actually stopping them being AntiBot's separate,
                    // IP-keyed ban system, not this account-level setting at all. This
                    // reuses sa_audit_log (already durably written on every failed
                    // login) so a script can't outrun the limit just by reconnecting.
                    if (plugin.getAuditLogService() != null) {
                        int recentFailures = plugin.getAuditLogService().countRecentFailures(uuid,
                                config.getSecurity().banDurationMinutes());
                        if (recentFailures >= config.getSecurity().maxLoginAttempts()) {
                            plugin.getMainThreadExecutor().execute(() -> player.kick(lang.buildKick("kick.banned",
                                    "minutes", String.valueOf(config.getSecurity().banDurationMinutes()))));
                            return;
                        }
                    }

                    boolean correct = passwords.verify(data.get().passwordHash(), password);

                    if (!correct) {
                        // Handle wrong password on main thread (UI only)
                        plugin.getMainThreadExecutor().execute(() -> {
                            state.incrementFailures();
                            String ip = state.getLoginIp();
                            plugin.getAntiBotService().recordFailedAttempt(ip);
                            webhook(WebhookService.Event.LOGIN_FAIL, player);
                            audit(AuditEvent.LOGIN_FAIL, player);
                            int remaining = config.getSecurity().maxLoginAttempts() - state.getFailedAttempts();
                            if (remaining <= 0) {
                                player.kick(lang.buildKick("kick.banned", "minutes",
                                        String.valueOf(config.getSecurity().banDurationMinutes())));
                            } else {
                                lang.send(player, "login.wrong-password", "attempts", String.valueOf(remaining));
                            }
                        });
                        return;
                    }

                    // Check 2FA status on virtual thread (avoids main-thread DB block)
                    boolean has2fa = totp.isEnabled(uuid);
                    plugin.getMainThreadExecutor().execute(() -> {
                        if (has2fa) {
                            state.markAwaiting2Fa();
                            lang.send(player, "login.require-2fa");
                        } else {
                            // LOGIN success — show login.success
                            completeAuth(player, state, false);
                            // SOFT ENFORCEMENT of two-factor.require-for-permission:
                            // 2FA setup (/2fa enable) itself requires being authenticated
                            // (see handleTwoFaEnable), so a hard block here would deadlock
                            // anyone who has never set it up. We therefore let login proceed
                            // and issue a persistent, hard-to-miss reminder instead. This is a
                            // real behavior change from before, where this config key was read
                            // but never actually checked anywhere — silently doing nothing.
                            String requiredPerm = config.getTwoFa().requireForPermission();
                            if (!requiredPerm.isBlank() && player.hasPermission(requiredPerm)) {
                                lang.send(player, "twofa.required-reminder");
                            }
                        }
                    });
                });
                return true;
            }
        };
    }

    public Command registerRegister() {
        return new CommandBase("register", lang) {
            @Override
            public boolean execute(@NotNull CommandSender sender, @NotNull String label, @NotNull String[] args) {
                if (!requirePlayer(sender))
                    return true;
                Player player = (Player) sender;
                UUID uuid = player.getUniqueId();

                if (args.length < 2) {
                    lang.send(player, "register.usage");
                    return true;
                }

                if (registerCooldown.isOnCooldown(uuid) && !player.hasPermission("secureauth.cooldown.bypass")) {
                    lang.send(player, "register.cooldown", "seconds",
                            String.valueOf(registerCooldown.remainingSeconds(uuid)));
                    return true;
                }
                if (!registerRateLimit.tryAcquire(uuid)) {
                    lang.send(player, "register.rate-limited");
                    return true;
                }

                String password = args[0];
                String confirm = args[1];

                if (!password.equals(confirm)) {
                    lang.send(player, "register.password-mismatch");
                    return true;
                }

                String error = passwords.validate(password);
                if (error != null) {
                    lang.send(player, error, "min", String.valueOf(config.getSecurity().passwordMinLength()), "max",
                            String.valueOf(config.getSecurity().passwordMaxLength()));
                    return true;
                }

                // SECURITY: same fix as /login — set the cooldown synchronously here,
                // before handing off to the virtual thread that hashes the password
                // (Argon2, deliberately slow). Setting it only after the DB insert
                // completes left a race window where several /register commands could
                // be accepted and start hashing concurrently before the first one's
                // cooldown ever took effect.
                registerCooldown.set(uuid);

                Thread.startVirtualThread(() -> {
                    if (playerData.getData(uuid).isPresent()) {
                        plugin.getMainThreadExecutor().execute(() -> lang.send(player, "register.already-registered"));
                        return;
                    }
                    String hash = passwords.hash(password);
                    // Use the IP captured in onPlayerLogin (getRealAddress) — same source as session.
                    String ip = playerData.getAuthState(uuid).getLoginIp();
                    PlayerData data = new PlayerData(uuid, player.getName(), hash, null, ip, null, null, null);
                    playerData.getRepository().insert(data);
                    playerData.invalidate(uuid);

                    plugin.getMainThreadExecutor().execute(() -> {
                        // REGISTER: do NOT auto-authenticate — player must /login explicitly.
                        // This is a deliberate security choice: forces confirmation that the
                        // player remembers the password they just typed.
                        lang.send(player, "register.success");
                        lang.send(player, "login.require-auth"); // "Войдите: /login <пароль>"
                        webhook(WebhookService.Event.REGISTER, player);
                        audit(AuditEvent.REGISTER, player);
                    });
                });
                return true;
            }
        };
    }

    public Command registerLogout() {
        return new CommandBase("logout", lang) {
            @Override
            public boolean execute(@NotNull CommandSender sender, @NotNull String label, @NotNull String[] args) {
                if (!requirePlayer(sender))
                    return true;
                Player player = (Player) sender;
                UUID uuid = player.getUniqueId();
                if (!playerData.isAuthenticated(uuid)) {
                    lang.send(player, "logout.not-logged-in");
                    return true;
                }
                playerData.getAuthState(uuid).markPending();
                sessions.invalidate(uuid);
                lang.send(player, "logout.success");
                webhook(WebhookService.Event.LOGOUT, player);
                audit(AuditEvent.LOGOUT, player);
                return true;
            }
        };
    }

    /**
     * /session — shows the account's trusted-session status (IP, created,
     * expires) so a player can notice an unfamiliar IP on their own account.
     * /session revoke — invalidates the trusted session WITHOUT demoting the
     * current connection back to pending, unlike /logout. Genuinely
     * different use case: "stop trusting whatever device/IP is currently
     * remembered" without also kicking yourself out of the game right now.
     */
    public Command registerSession() {
        return new CommandBase("session", lang) {
            @Override
            public boolean execute(@NotNull CommandSender sender, @NotNull String label, @NotNull String[] args) {
                if (!requirePlayer(sender))
                    return true;
                Player player = (Player) sender;
                UUID uuid = player.getUniqueId();
                if (!playerData.isAuthenticated(uuid)) {
                    lang.send(player, "login.require-auth");
                    return true;
                }

                if (args.length >= 1 && args[0].equalsIgnoreCase("revoke")) {
                    Thread.startVirtualThread(() -> {
                        var existing = sessions.getSessionInfo(uuid);
                        sessions.invalidate(uuid);
                        plugin.getMainThreadExecutor().execute(() -> {
                            if (existing.isEmpty()) {
                                lang.send(player, "session.revoke-none");
                            } else {
                                lang.send(player, "session.revoke-success");
                            }
                        });
                    });
                    return true;
                }

                Thread.startVirtualThread(() -> {
                    var info = sessions.getSessionInfo(uuid);
                    plugin.getMainThreadExecutor().execute(() -> {
                        if (info.isEmpty()) {
                            lang.send(player, "session.none");
                            return;
                        }
                        var s = info.get();
                        lang.send(player, s.expired() ? "session.status-expired" : "session.status-active", "ip",
                                s.ip(), "created", s.createdAt(), "expires", s.expiresAt());
                    });
                });
                return true;
            }
        };
    }

    public Command registerChangePassword() {
        return new CommandBase("changepassword", lang) {
            @Override
            public boolean execute(@NotNull CommandSender sender, @NotNull String label, @NotNull String[] args) {
                if (!requirePlayer(sender))
                    return true;
                Player player = (Player) sender;
                UUID uuid = player.getUniqueId();
                if (!playerData.isAuthenticated(uuid)) {
                    lang.send(player, "changepassword.not-logged-in");
                    return true;
                }
                if (args.length < 2) {
                    lang.send(player, "changepassword.usage");
                    return true;
                }
                String oldPw = args[0], newPw = args[1];
                Thread.startVirtualThread(() -> {
                    Optional<PlayerData> data = playerData.getData(uuid);
                    if (data.isEmpty())
                        return;
                    if (!passwords.verify(data.get().passwordHash(), oldPw)) {
                        plugin.getMainThreadExecutor().execute(() -> lang.send(player, "changepassword.wrong-old"));
                        return;
                    }
                    if (oldPw.equals(newPw)) {
                        plugin.getMainThreadExecutor().execute(() -> lang.send(player, "changepassword.same-password"));
                        return;
                    }
                    playerData.getRepository().updatePassword(uuid, passwords.hash(newPw));
                    playerData.invalidate(uuid);
                    sessions.invalidate(uuid);
                    plugin.getMainThreadExecutor().execute(() -> {
                        lang.send(player, "changepassword.success");
                        audit(AuditEvent.PASSWORD_CHANGE, player);
                    });
                });
                return true;
            }
        };
    }

    public Command registerTwoFa() {
        return new CommandBase("2fa", lang) {
            @Override
            public boolean execute(@NotNull CommandSender sender, @NotNull String label, @NotNull String[] args) {
                if (!requirePlayer(sender))
                    return true;
                Player player = (Player) sender;
                UUID uuid = player.getUniqueId();
                if (args.length == 0) {
                    lang.send(player, "twofa.usage");
                    return true;
                }
                switch (args[0].toLowerCase()) {
                    case "enable" -> handleTwoFaEnable(player, uuid, args);
                    case "disable" -> handleTwoFaDisable(player, uuid, args);
                    case "backup" -> handleTwoFaBackup(player, uuid);
                    default -> {
                        if (playerData.getAuthState(uuid).isAwaiting2Fa()) {
                            handleTwoFaVerify(player, uuid, args[0]);
                        } else {
                            lang.send(player, "twofa.usage");
                        }
                    }
                }
                return true;
            }
        };
    }

    public Command registerRecover() {
        return new CommandBase("recover", lang) {
            @Override
            public boolean execute(@NotNull CommandSender sender, @NotNull String label, @NotNull String[] args) {
                if (!requirePlayer(sender))
                    return true;
                Player player = (Player) sender;
                UUID uuid = player.getUniqueId();

                if (!email.isEnabled()) {
                    lang.send(player, "recovery.disabled");
                    return true;
                }

                // /recover confirm <token> <newPassword>
                if (args.length >= 1 && args[0].equalsIgnoreCase("confirm")) {
                    if (args.length < 3) {
                        lang.send(player, "recovery.confirm-usage");
                        return true;
                    }
                    if (!recoveryRateLimit.tryAcquire(uuid)) {
                        lang.send(player, "recovery.rate-limited");
                        return true;
                    }
                    String token = args[1];
                    String newPassword = args[2];
                    Thread.startVirtualThread(() -> {
                        String error = passwords.validate(newPassword);
                        if (error != null) {
                            plugin.getMainThreadExecutor()
                                    .execute(() -> lang.send(player, error, "min",
                                            String.valueOf(config.getSecurity().passwordMinLength()), "max",
                                            String.valueOf(config.getSecurity().passwordMaxLength())));
                            return;
                        }
                        boolean ok = playerData.getRecoveryRepository().findValidHash(uuid)
                                .filter(stored -> constantTimeEquals(stored, EmailService.hashToken(token)))
                                .isPresent();
                        plugin.getMainThreadExecutor().execute(() -> {
                            if (!ok) {
                                lang.send(player, "recovery.invalid-token");
                                return;
                            }
                            Thread.startVirtualThread(() -> {
                                String hash = passwords.hash(newPassword);
                                playerData.getRepository().updatePassword(uuid, hash);
                                playerData.getRecoveryRepository().delete(uuid);
                                playerData.invalidate(uuid);
                                sessions.invalidate(uuid);
                                if (plugin.getAuditLogService() != null) {
                                    plugin.getAuditLogService().logAsync(AuditEvent.PASSWORD_RESET, uuid,
                                            player.getName(), playerData.getAuthState(uuid).getLoginIp(),
                                            "via /recover");
                                }
                                plugin.getMainThreadExecutor()
                                        .execute(() -> lang.send(player, "recovery.confirm-success"));
                            });
                        });
                    });
                    return true;
                }

                // /recover — sends a reset token to the account's VERIFIED email on file.
                // SECURITY: this intentionally takes no email argument. Accepting an
                // email as user input here would let anyone already connected as this
                // Minecraft account (exactly the scenario the SecureAuth password exists
                // to guard against — shared/stolen sessions, offline-mode name-claiming)
                // redirect the reset token to an address they control, bypassing the
                // password entirely without ever proving they own the account's real
                // email. See /setemail for the only way to link/change that address,
                // which requires already being authenticated plus verifying receipt.
                Optional<PlayerData> data = playerData.getData(uuid);
                String onFileEmail = data.map(PlayerData::email).orElse(null);
                if (onFileEmail == null || onFileEmail.isBlank()) {
                    lang.send(player, "recovery.no-email-linked");
                    return true;
                }
                if (emailSendCooldown.isOnCooldown(uuid) && !player.hasPermission("secureauth.cooldown.bypass")) {
                    lang.send(player, "recovery.cooldown", "seconds",
                            String.valueOf(emailSendCooldown.remainingSeconds(uuid)));
                    return true;
                }
                emailSendCooldown.set(uuid);
                String token = email.generateToken();
                int ttl = config.getEmail().recoveryTokenTtlMinutes();

                Thread.startVirtualThread(() -> {
                    // Store the hash BEFORE sending the email — if the send fails we still
                    // invalidate any prior token below via save()'s delete-then-insert, so a
                    // failed send never leaves a stale, still-valid token lying around silently.
                    playerData.getRecoveryRepository().save(uuid, EmailService.hashToken(token), ttl);
                    email.sendRecoveryEmail(onFileEmail, player.getName(), token)
                            .thenAccept(success -> plugin.getMainThreadExecutor().execute(() -> {
                                if (success) {
                                    lang.send(player, "recovery.sent", "email", maskEmail(onFileEmail));
                                } else {
                                    lang.send(player, "recovery.failed");
                                }
                            }));
                });
                return true;
            }
        };
    }

    /** Masks an email for display, e.g. "jo***@example.com", so it isn't fully shown on-screen. */
    private static String maskEmail(String email) {
        int at = email.indexOf('@');
        if (at <= 1)
            return email;
        String local = email.substring(0, at);
        String visible = local.substring(0, Math.min(2, local.length()));
        return visible + "***" + email.substring(at);
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null)
            return false;
        return java.security.MessageDigest.isEqual(a.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                b.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * /setemail <email> — request linking a new recovery email.
     * /setemail confirm <token> — verify receipt and actually save it.
     *
     * <p>Requires the player to already be authenticated (know their current
     * password) — this is what prevents the /recover bypass: an attacker who
     * merely controls the Minecraft session cannot both set an arbitrary
     * recovery email AND immediately use it, because setting one requires
     * already having passed the password check this whole plugin exists for.
     */
    public Command registerSetEmail() {
        return new CommandBase("setemail", lang) {
            @Override
            public boolean execute(@NotNull CommandSender sender, @NotNull String label, @NotNull String[] args) {
                if (!requirePlayer(sender))
                    return true;
                Player player = (Player) sender;
                UUID uuid = player.getUniqueId();

                if (!playerData.isAuthenticated(uuid)) {
                    lang.send(player, "login.require-auth");
                    return true;
                }
                if (!email.isEnabled()) {
                    lang.send(player, "recovery.disabled");
                    return true;
                }
                if (args.length < 1) {
                    lang.send(player, "setemail.usage");
                    return true;
                }

                // /setemail confirm <token>
                if (args[0].equalsIgnoreCase("confirm")) {
                    if (args.length < 2) {
                        lang.send(player, "setemail.confirm-usage");
                        return true;
                    }
                    if (!recoveryRateLimit.tryAcquire(uuid)) {
                        lang.send(player, "recovery.rate-limited");
                        return true;
                    }
                    String token = args[1];
                    Thread.startVirtualThread(() -> {
                        var pending = playerData.getEmailChangeRepository().findValid(uuid);
                        boolean ok = pending
                                .filter(p -> constantTimeEquals(p.tokenHash(), EmailService.hashToken(token)))
                                .isPresent();
                        if (ok) {
                            String newEmail = pending.get().email();
                            playerData.getRepository().updateEmail(uuid, newEmail);
                            playerData.getEmailChangeRepository().delete(uuid);
                            playerData.invalidate(uuid);
                            if (plugin.getAuditLogService() != null) {
                                plugin.getAuditLogService().logAsync(AuditEvent.EMAIL_CHANGED, uuid, player.getName(),
                                        playerData.getAuthState(uuid).getLoginIp(), "linked " + maskEmail(newEmail));
                            }
                        }
                        plugin.getMainThreadExecutor().execute(() -> {
                            if (ok) {
                                lang.send(player, "setemail.confirm-success");
                            } else {
                                lang.send(player, "setemail.invalid-token");
                            }
                        });
                    });
                    return true;
                }

                // /setemail <email> — send a verification token to the NEW address.
                // Nothing is saved to the account until /setemail confirm succeeds.
                String newEmail = args[0];
                if (!newEmail.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")) {
                    lang.send(player, "setemail.invalid-format");
                    return true;
                }
                if (emailSendCooldown.isOnCooldown(uuid) && !player.hasPermission("secureauth.cooldown.bypass")) {
                    lang.send(player, "recovery.cooldown", "seconds",
                            String.valueOf(emailSendCooldown.remainingSeconds(uuid)));
                    return true;
                }
                emailSendCooldown.set(uuid);
                String token = email.generateToken();
                int ttl = config.getEmail().recoveryTokenTtlMinutes();
                Thread.startVirtualThread(() -> {
                    playerData.getEmailChangeRepository().save(uuid, newEmail, EmailService.hashToken(token), ttl);
                    email.sendVerificationEmail(newEmail, player.getName(), token)
                            .thenAccept(success -> plugin.getMainThreadExecutor().execute(() -> {
                                if (success) {
                                    lang.send(player, "setemail.sent", "email", maskEmail(newEmail));
                                } else {
                                    lang.send(player, "recovery.failed");
                                }
                            }));
                });
                return true;
            }
        };
    }

    // ── Core auth completion ─────────────────────────────────────────────────

    /**
     * Completes authentication: sets state, removes blindness, creates session.
     *
     * @param silent if {@code true}, suppresses {@code login.success} message.
     *               Use {@code true} after /register (register.success already covers it).
     *               Use {@code false} after /login and /2fa verify.
     */
    private void completeAuth(Player player, AuthState state, boolean silent) {
        AuthApi.Stage previous = AuthApi.Stage.valueOf(state.getStage().name());
        state.markAuthenticated();
        state.resetFailures();
        // Remove blindness. Schedule 1 tick later so Paper has processed the join packet
        // before we send the effect removal — avoids a race where add and remove happen
        // in the same tick and the client never sees the clear.
        plugin.getServer().getScheduler().runTaskLater(plugin,
                () -> player.removePotionEffect(PotionEffectType.BLINDNESS), 1L);
        // Use the IP captured in onPlayerLogin (getRealAddress) — single source of truth.
        // player.getAddress() may return a different IP when the server is behind a proxy.
        String ip = state.getLoginIp();
        UUID uuid = player.getUniqueId();
        plugin.getDebugLogger().log("[Auth] completeAuth uuid={} ip={} silent={}", uuid, ip, silent);
        // sessions.create() is synchronous (blocking DB write) — must run off the
        // main thread.  Combine with updateLastLogin in a single virtual thread so
        // both DB writes happen together without blocking the server tick.
        Thread.startVirtualThread(() -> {
            plugin.getDebugLogger().log("[Auth] VT: calling sessions.create uuid={}", uuid);
            sessions.create(uuid, ip); // blocking, must complete before next join
            plugin.getDebugLogger().log("[Auth] VT: sessions.create done, calling updateLastLogin uuid={}", uuid);
            playerData.getRepository().updateLastLogin(uuid, ip);
            plugin.getDebugLogger().log("[Auth] VT: all DB writes done uuid={}", uuid);
        });
        if (!silent) {
            lang.send(player, "login.success");
            webhook(WebhookService.Event.LOGIN, player);
            audit(AuditEvent.LOGIN, player);
        }
        // Notify public API listeners regardless
        if (plugin.getAuthApiImpl() != null) {
            plugin.getAuthApiImpl().fireListeners(player.getUniqueId(), previous, AuthApi.Stage.AUTHENTICATED);
        }
    }

    // ── 2FA helpers ──────────────────────────────────────────────────────────

    private void handleTwoFaEnable(Player player, UUID uuid, String[] args) {
        if (!playerData.isAuthenticated(uuid)) {
            lang.send(player, "general.not-logged-in");
            return;
        }
        if (args.length == 1) {
            TotpService.TotpSetupData setup = totp.startSetup(uuid, player.getName());
            if (setup.qrImageUrl() != null) {
                lang.send(player, "twofa.enable.start", "secret", setup.secret(), "qr-url", setup.qrImageUrl(),
                        "qr-uri", setup.qrUri());
            } else {
                lang.send(player, "twofa.enable.start-manual", "secret", setup.secret());
            }
        } else {
            Thread.startVirtualThread(() -> {
                boolean ok = totp.confirmSetup(uuid, args[1]);
                plugin.getMainThreadExecutor().execute(() -> {
                    if (ok) {
                        lang.send(player, "twofa.enable.success", "backup-codes",
                                String.join("\n", totp.getBackupCodes(uuid)));
                        webhook(WebhookService.Event.TOTP_ENABLE, player);
                        audit(AuditEvent.TOTP_ENABLE, player);
                    } else {
                        lang.send(player, "twofa.enable.invalid-code");
                    }
                });
            });
        }
    }

    private void handleTwoFaDisable(Player player, UUID uuid, String[] args) {
        if (!playerData.isAuthenticated(uuid)) {
            lang.send(player, "general.not-logged-in");
            return;
        }
        if (args.length < 2) {
            lang.send(player, "twofa.disable.confirm-usage");
            return;
        }
        Thread.startVirtualThread(() -> {
            boolean ok = totp.disable(uuid, args[1]);
            plugin.getMainThreadExecutor().execute(() -> {
                lang.send(player, ok ? "twofa.disable.success" : "twofa.disable.invalid-code");
                if (ok) {
                    webhook(WebhookService.Event.TOTP_DISABLE, player);
                    audit(AuditEvent.TOTP_DISABLE, player);
                }
            });
        });
    }

    private void handleTwoFaVerify(Player player, UUID uuid, String code) {
        if (!totpRateLimit.tryAcquire(uuid)) {
            lang.send(player, "twofa.verify.rate-limited");
            return;
        }
        Thread.startVirtualThread(() -> {
            boolean ok = totp.verify(uuid, code);
            plugin.getMainThreadExecutor().execute(() -> {
                if (ok) {
                    // 2FA verify is a LOGIN completion — not silent
                    completeAuth(player, playerData.getAuthState(uuid), false);
                    lang.send(player, "twofa.verify.success");
                } else {
                    AuthState state = playerData.getAuthState(uuid);
                    state.incrementFailures();
                    int remaining = config.getSecurity().maxLoginAttempts() - state.getFailedAttempts();
                    lang.send(player, "twofa.verify.invalid-code", "attempts", String.valueOf(Math.max(0, remaining)));
                }
            });
        });
    }

    private void handleTwoFaBackup(Player player, UUID uuid) {
        if (!playerData.isAuthenticated(uuid)) {
            lang.send(player, "general.not-logged-in");
            return;
        }
        Thread.startVirtualThread(() -> {
            var codes = totp.getBackupCodes(uuid);
            plugin.getMainThreadExecutor()
                    .execute(() -> lang.send(player, "twofa.backup.list", "codes", String.join("\n", codes)));
        });
    }

    // ── Webhook helper ───────────────────────────────────────────────────────

    private void webhook(WebhookService.Event event, Player player) {
        var ws = plugin.getWebhookService();
        if (ws == null)
            return;
        String ip = playerData.getAuthState(player.getUniqueId()).getLoginIp();
        ws.fireAsync(event, player.getName(), player.getUniqueId(), ip);
    }

    private void audit(AuditEvent event, Player player) {
        var al = plugin.getAuditLogService();
        if (al == null)
            return;
        String ip = playerData.getAuthState(player.getUniqueId()).getLoginIp();
        al.logAsync(event, player.getUniqueId(), player.getName(), ip);
    }
}
