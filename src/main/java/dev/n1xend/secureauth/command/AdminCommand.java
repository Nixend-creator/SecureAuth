package dev.n1xend.secureauth.command;

import dev.n1xend.secureauth.SecureAuthPlugin;
import dev.n1xend.secureauth.antibot.AntiBotService;
import dev.n1xend.secureauth.audit.AuditEntry;
import dev.n1xend.secureauth.audit.AuditEvent;
import dev.n1xend.secureauth.audit.AuditLogService;
import dev.n1xend.secureauth.debug.DebugLogger;
import dev.n1xend.secureauth.i18n.LanguageManager;
import dev.n1xend.secureauth.module.ModuleManager;
import dev.n1xend.secureauth.module.ReloadResult;
import dev.n1xend.secureauth.player.PlayerDataService;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;

import java.util.List;
import java.util.UUID;

/**
 * Admin command: /saadmin
 *
 * <p>Subcommands: reload, forcelogin, resetpassword, unban, debug
 */
public final class AdminCommand {

    private final SecureAuthPlugin plugin;
    private final LanguageManager lang;
    private final PlayerDataService playerData;
    private final ModuleManager modules;
    private final AntiBotService antiBot;
    private final DebugLogger debug;

    public AdminCommand(SecureAuthPlugin plugin, LanguageManager lang, PlayerDataService playerData,
            ModuleManager modules, AntiBotService antiBot, DebugLogger debug) {
        this.plugin = plugin;
        this.lang = lang;
        this.playerData = playerData;
        this.modules = modules;
        this.antiBot = antiBot;
        this.debug = debug;
    }

    public Command build() {
        return new CommandBase("saadmin", lang) {
            @Override
            public boolean execute(@NotNull CommandSender sender, @NotNull String label, @NotNull String[] args) {
                if (!requirePermission(sender, "secureauth.admin"))
                    return true;

                if (args.length == 0) {
                    sender.sendMessage("/saadmin reload|forcelogin|resetpassword|unban|debug|history|stats|listbans");
                    return true;
                }

                switch (args[0].toLowerCase()) {
                    case "reload" -> handleReload(sender);
                    case "forcelogin" -> handleForceLogin(sender, args);
                    case "resetpassword" -> handleResetPassword(sender, args);
                    case "unban" -> handleUnban(sender, args);
                    case "debug" -> handleDebug(sender);
                    case "history" -> handleHistory(sender, args);
                    case "stats" -> handleStats(sender);
                    case "listbans" -> handleListBans(sender);
                    default -> sender.sendMessage("Unknown subcommand: " + args[0]);
                }
                return true;
            }
        };
    }

    // ── Subcommand handlers ──────────────────────────────────────────────────

    private void handleReload(CommandSender sender) {
        lang.send(sender, "admin.reload.start");
        long startTotal = System.currentTimeMillis();

        List<ReloadResult> results = modules.reloadAll();

        for (ReloadResult r : results) {
            if (r.success()) {
                lang.send(sender, "admin.reload.module-ok", "module", r.moduleName(), "ms",
                        String.valueOf(r.durationMs()));
            } else {
                lang.send(sender, "admin.reload.module-failed", "module", r.moduleName(), "error",
                        String.valueOf(r.error()));
            }
        }

        long total = System.currentTimeMillis() - startTotal;
        lang.send(sender, "admin.reload.done", "total-ms", String.valueOf(total));
    }

    private void handleForceLogin(CommandSender sender, String[] args) {
        if (!requirePermission(sender, "secureauth.admin.forcelogin"))
            return;
        if (args.length < 2) {
            lang.send(sender, "admin.forcelogin.usage");
            return;
        }

        Player target = plugin.getServer().getPlayerExact(args[1]);
        if (target == null) {
            lang.send(sender, "admin.forcelogin.not-found", "player", args[1]);
            return;
        }

        playerData.getAuthState(target.getUniqueId()).markAuthenticated();
        target.removePotionEffect(org.bukkit.potion.PotionEffectType.BLINDNESS);
        lang.send(sender, "admin.forcelogin.success", "player", target.getName());
        if (plugin.getAuditLogService() != null && target.getAddress() != null) {
            String adminName = (sender instanceof Player p) ? p.getName() : "Console";
            plugin.getAuditLogService().logAsync(AuditEvent.FORCE_LOGIN, target.getUniqueId(), target.getName(),
                    target.getAddress().getAddress().getHostAddress(), "by " + adminName);
        }
    }

    private void handleResetPassword(CommandSender sender, String[] args) {
        if (!requirePermission(sender, "secureauth.admin.resetpassword"))
            return;
        if (args.length < 3) {
            lang.send(sender, "admin.resetpassword.usage");
            return;
        }

        String targetName = args[1];
        String newPassword = args[2];

        Thread.startVirtualThread(() -> {
            // getPlayerUniqueId() can return null for unknown players
            UUID targetUuid = plugin.getServer().getPlayerUniqueId(targetName);
            if (targetUuid == null) {
                plugin.getMainThreadExecutor()
                        .execute(() -> lang.send(sender, "admin.resetpassword.not-found", "player", targetName));
                return;
            }
            if (playerData.getRepository().findByUuid(targetUuid).isEmpty()) {
                plugin.getMainThreadExecutor()
                        .execute(() -> lang.send(sender, "admin.resetpassword.not-found", "player", targetName));
                return;
            }
            String newHash = plugin.getPasswordService().hash(newPassword);
            playerData.getRepository().updatePassword(targetUuid, newHash);
            playerData.invalidate(targetUuid);
            if (plugin.getAuditLogService() != null) {
                String adminName = (sender instanceof Player p) ? p.getName() : "Console";
                plugin.getAuditLogService().logAsync(AuditEvent.PASSWORD_RESET, targetUuid, targetName, "admin",
                        "by " + adminName);
            }
            plugin.getMainThreadExecutor().execute(() -> {
                lang.send(sender, "admin.resetpassword.success", "player", targetName);
                Player online = plugin.getServer().getPlayerExact(targetName);
                if (online != null)
                    lang.send(online, "admin.resetpassword.notify");
            });
        });
    }

    private void handleUnban(CommandSender sender, String[] args) {
        if (!requirePermission(sender, "secureauth.admin.unban"))
            return;
        if (args.length < 2) {
            lang.send(sender, "admin.unban.usage");
            return;
        }

        String ip = args[1];
        if (antiBot.isBanned(ip)) {
            antiBot.unbanIp(ip);
            lang.send(sender, "admin.unban.success", "ip", ip);
        } else {
            lang.send(sender, "admin.unban.not-banned", "ip", ip);
        }
    }

    private void handleDebug(CommandSender sender) {
        if (!requirePermission(sender, "secureauth.admin.debug"))
            return;
        debug.toggle();
        lang.send(sender, debug.isEnabled() ? "admin.debug.enabled" : "admin.debug.disabled");
    }

    private void handleHistory(CommandSender sender, String[] args) {
        if (!requirePermission(sender, "secureauth.admin.history"))
            return;
        if (args.length < 2) {
            lang.send(sender, "admin.history.usage");
            return;
        }

        String targetName = args[1];

        Thread.startVirtualThread(() -> {
            try {
                UUID targetUuid = plugin.getServer().getPlayerUniqueId(targetName);
                if (targetUuid == null) {
                    plugin.getMainThreadExecutor()
                            .execute(() -> lang.send(sender, "admin.history.not-found", "player", targetName));
                    return;
                }

                AuditLogService al = plugin.getAuditLogService();
                List<AuditEntry> entries = al.getHistory(targetUuid);

                plugin.getMainThreadExecutor().execute(() -> {
                    if (entries.isEmpty()) {
                        lang.send(sender, "admin.history.empty", "player", targetName);
                        return;
                    }
                    lang.send(sender, "admin.history.header", "player", targetName, "count",
                            String.valueOf(entries.size()));
                    for (AuditEntry e : entries) {
                        String detail = e.details() != null ? " <gray>(" + e.details() + ")</gray>" : "";
                        String ts = e.createdAt().length() > 16 ? e.createdAt().substring(0, 16) : e.createdAt();
                        lang.send(sender, "admin.history.entry", "time", ts, "event", e.event().name(), "ip", e.ip(),
                                "detail", detail);
                    }
                });
            } catch (Exception e) {
                plugin.getMainThreadExecutor()
                        .execute(() -> sender.sendMessage("[SecureAuth] history error: " + e.getMessage()));
                plugin.getSLF4JLogger().warn("[Admin] /saadmin history failed: {}", e.getMessage(), e);
            }
        });
    }

    private void handleStats(CommandSender sender) {
        if (!requirePermission(sender, "secureauth.admin.stats"))
            return;

        int online = plugin.getServer().getOnlinePlayers().size();

        Thread.startVirtualThread(() -> {
            try {
                AuditLogService.Stats s = plugin.getAuditLogService().getStats(online);
                plugin.getMainThreadExecutor().execute(() -> {
                    lang.send(sender, "admin.stats.header");
                    lang.send(sender, "admin.stats.players", "online", String.valueOf(s.onlinePlayers()), "total",
                            String.valueOf(s.totalPlayers()));
                    lang.send(sender, "admin.stats.sessions", "active", String.valueOf(s.activeSessions()));
                    lang.send(sender, "admin.stats.bans", "active", String.valueOf(s.activeBans()));
                    lang.send(sender, "admin.stats.fails", "count", String.valueOf(s.failsLastHour()));
                    lang.send(sender, "admin.stats.registrations", "count", String.valueOf(s.registrationsToday()));
                });
            } catch (Exception e) {
                plugin.getMainThreadExecutor()
                        .execute(() -> sender.sendMessage("[SecureAuth] stats error: " + e.getMessage()));
                plugin.getSLF4JLogger().warn("[Admin] /saadmin stats failed: {}", e.getMessage(), e);
            }
        });
    }

    private void handleListBans(CommandSender sender) {
        if (!requirePermission(sender, "secureauth.admin.listbans"))
            return;

        Thread.startVirtualThread(() -> {
            List<AuditLogService.BanEntry> bans = plugin.getAuditLogService().getActiveBans();

            plugin.getMainThreadExecutor().execute(() -> {
                if (bans.isEmpty()) {
                    lang.send(sender, "admin.listbans.empty");
                    return;
                }
                lang.send(sender, "admin.listbans.header", "count", String.valueOf(bans.size()));
                for (AuditLogService.BanEntry b : bans) {
                    String expires = b.expiresAt() != null
                            ? b.expiresAt().substring(0, Math.min(16, b.expiresAt().length()))
                            : "∞";
                    lang.send(sender, "admin.listbans.entry", "ip", b.ip(), "reason", b.reason(), "expires", expires);
                }
            });
        });
    }

    private boolean requirePermission(CommandSender sender, String permission) {
        if (!sender.hasPermission(permission)) {
            lang.send(sender, "admin.no-permission");
            return false;
        }
        return true;
    }
}
