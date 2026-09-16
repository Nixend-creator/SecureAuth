package dev.n1xend.secureauth.listener;

import dev.n1xend.secureauth.config.PluginConfig;
import dev.n1xend.secureauth.i18n.LanguageManager;
import dev.n1xend.secureauth.player.PlayerDataService;
import io.papermc.paper.event.player.AsyncChatEvent;
import org.bukkit.entity.Player;
import org.bukkit.event.Cancellable;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.player.*;

import java.util.List;
import java.util.concurrent.Executor;
import java.util.regex.Pattern;

/**
 * Cancels interactions for players who have not yet authenticated.
 */
public final class ProtectionListener implements Listener {

    private final PlayerDataService playerData;
    private final LanguageManager lang;
    private final PluginConfig config;
    private final Executor mainThreadExecutor;

    public ProtectionListener(PlayerDataService playerData, LanguageManager lang, PluginConfig config,
            Executor mainThreadExecutor) {
        this.playerData = playerData;
        this.lang = lang;
        this.config = config;
        this.mainThreadExecutor = mainThreadExecutor;
    }

    /**
     * Matches a chat message that looks like one of SecureAuth's sensitive
     * commands typed WITHOUT the leading {@code /} — e.g. a player who meant
     * to run {@code /changepassword oldpass newpass} but forgot the slash and
     * hit enter, sending their old and new password as a plain, PUBLIC chat
     * message to everyone nearby, any chat-logging plugin, and any Discord
     * chat bridge. Group 1 captures the intended command + arguments so it
     * can be re-dispatched with the slash restored.
     */
    private static final List<Pattern> ACCIDENTAL_COMMAND_PATTERNS = List.of(
            Pattern.compile("(?i)^((?:login|l)\\s+\\S.*)$"), Pattern.compile("(?i)^((?:register|reg)\\s+\\S.*)$"),
            Pattern.compile("(?i)^(changepassword\\s+\\S.*)$"), Pattern.compile("(?i)^(2fa\\s+\\S.*)$"),
            Pattern.compile("(?i)^(setemail\\s+\\S.*)$"), Pattern.compile("(?i)^(recover(?:\\s+confirm\\s+\\S.*)?)$"));

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onChat(AsyncChatEvent event) {
        Player player = event.getPlayer();
        if (!playerData.isAuthenticated(player.getUniqueId())) {
            event.setCancelled(true);
            return;
        }

        // SAFETY NET: an already-authenticated player who forgets the leading
        // "/" on a sensitive command (e.g. types "changepassword old new" as
        // plain chat instead of "/changepassword old new") would otherwise
        // have their password/2FA code broadcast in full to every nearby
        // player, any chat-logging plugin, and any Discord chat bridge — the
        // exact same category of plaintext-secret leak this project already
        // fixed for the server console via LogRedactionFilter, just via a
        // different channel. Intercept, cancel, and re-dispatch as the
        // intended slash command instead.
        String plain = net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer.plainText()
                .serialize(event.message());
        for (Pattern p : ACCIDENTAL_COMMAND_PATTERNS) {
            var m = p.matcher(plain);
            if (m.matches()) {
                event.setCancelled(true);
                String commandLine = m.group(1);
                lang.send(player, "general.chat-command-redirected");
                // PlayerCommandPreprocessEvent/performCommand must run on the main
                // thread; AsyncChatEvent handlers do not run there.
                mainThreadExecutor.execute(() -> player.performCommand(commandLine));
                return;
            }
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onCommand(PlayerCommandPreprocessEvent event) {
        Player player = event.getPlayer();
        if (playerData.isAuthenticated(player.getUniqueId()))
            return;

        String cmd = event.getMessage().toLowerCase();
        // Allow auth commands
        if (cmd.startsWith("/login") || cmd.startsWith("/register") || cmd.startsWith("/l ") || cmd.startsWith("/reg ")
                || cmd.startsWith("/2fa") || cmd.startsWith("/recover")) {
            return;
        }
        event.setCancelled(true);
        lang.send(player, "general.not-logged-in");
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onMove(PlayerMoveEvent event) {
        Player player = event.getPlayer();
        if (playerData.isAuthenticated(player.getUniqueId()))
            return;
        // FIX: this previously ignored auth.block-movement entirely and always
        // blocked horizontal movement — an admin who explicitly set this to
        // false (e.g. to let players walk around a waiting-room spawn while
        // typing their password) had no way to actually get that behavior.
        if (!config.getAuth().blockMovement())
            return;

        var from = event.getFrom();
        var to = event.getTo();
        if (to != null && (from.getBlockX() != to.getBlockX() || from.getBlockZ() != to.getBlockZ())) {
            event.setTo(from.toLocation(from.getWorld()));
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onBlockBreak(BlockBreakEvent event) {
        blockIfUnauthenticated(event.getPlayer(), event);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onBlockPlace(BlockPlaceEvent event) {
        blockIfUnauthenticated(event.getPlayer(), event);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInventoryClick(InventoryClickEvent event) {
        if (event.getWhoClicked() instanceof Player player) {
            if (!playerData.isAuthenticated(player.getUniqueId())) {
                event.setCancelled(true);
            }
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onEntityDamage(EntityDamageByEntityEvent event) {
        if (event.getDamager() instanceof Player p && !playerData.isAuthenticated(p.getUniqueId())) {
            event.setCancelled(true);
        }
        if (event.getEntity() instanceof Player p && !playerData.isAuthenticated(p.getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onDrop(PlayerDropItemEvent event) {
        blockIfUnauthenticated(event.getPlayer(), event);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onPickup(PlayerAttemptPickupItemEvent event) {
        blockIfUnauthenticated(event.getPlayer(), event);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInteract(PlayerInteractEvent event) {
        blockIfUnauthenticated(event.getPlayer(), event);
    }

    private void blockIfUnauthenticated(Player player, Cancellable event) {
        if (!playerData.isAuthenticated(player.getUniqueId())) {
            event.setCancelled(true);
        }
    }
}
