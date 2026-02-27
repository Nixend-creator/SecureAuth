package dev.n1xend.secureauth.integration;

import org.bukkit.plugin.java.JavaPlugin;
import org.slf4j.Logger;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Soft-depend integration with LuckPerms.
 *
 * <p><strong>Classloading isolation:</strong> LuckPerms API types are only referenced
 * inside {@link LuckPermsDelegate} which is loaded lazily — only when LuckPerms is
 * confirmed present on the server. This prevents {@code NoClassDefFoundError} when
 * LuckPerms is not installed, because the JVM never attempts to resolve LP classes
 * during loading of this outer class.
 */
public final class LuckPermsIntegration {

    private final JavaPlugin plugin;
    private final Logger log;

    /** Non-null only when LuckPerms is present and loaded. */
    private LuckPermsDelegate delegate;

    public LuckPermsIntegration(JavaPlugin plugin, Logger log) {
        this.plugin = plugin;
        this.log = log;
    }

    /**
     * Checks for LuckPerms and, if present, instantiates the delegate.
     * Safe to call regardless of whether LuckPerms is installed.
     */
    public boolean setup() {
        if (plugin.getServer().getPluginManager().getPlugin("LuckPerms") == null) {
            log.info("[LuckPerms] Not found — integration disabled.");
            return false;
        }
        // Only NOW do we load LuckPermsDelegate (and therefore any LP API classes)
        try {
            delegate = new LuckPermsDelegate();
            delegate.init();
            log.info("[LuckPerms] Integration enabled.");
            return true;
        } catch (Exception e) {
            log.warn("[LuckPerms] Could not initialise: {}", e.getMessage());
            return false;
        }
    }

    public boolean isAvailable() {
        return delegate != null;
    }

    /** Returns the player's primary group. Falls back to {@code "default"} if LP absent. */
    public CompletableFuture<String> getPrimaryGroup(UUID uuid) {
        if (!isAvailable())
            return CompletableFuture.completedFuture("default");
        return delegate.getPrimaryGroup(uuid);
    }

    /** Grants a temporary permission. No-op if LP absent. */
    public CompletableFuture<Void> grantPermissionTemporary(UUID uuid, String permission, Duration duration) {
        if (!isAvailable())
            return CompletableFuture.completedFuture(null);
        return delegate.grantPermissionTemporary(uuid, permission, duration);
    }

    // ── Inner delegate — LP API classes referenced only here ─────────────────
    //
    // This class is only loaded when LuckPerms is confirmed present.
    // Keeping all LP imports in a separate class prevents the JVM from trying to
    // resolve net.luckperms.** when LuckPermsIntegration itself is first loaded.

    private static final class LuckPermsDelegate {

        // Imports here — safe because this class is only instantiated after LP is found
        private net.luckperms.api.LuckPerms api;

        void init() {
            api = net.luckperms.api.LuckPermsProvider.get();
        }

        CompletableFuture<String> getPrimaryGroup(UUID uuid) {
            return api.getUserManager().loadUser(uuid).thenApply(net.luckperms.api.model.user.User::getPrimaryGroup);
        }

        CompletableFuture<Void> grantPermissionTemporary(UUID uuid, String permission, Duration duration) {
            return api.getUserManager().loadUser(uuid).thenAccept(user -> {
                user.data().add(net.luckperms.api.node.types.PermissionNode.builder(permission)
                        .expiry(java.time.Instant.now().plus(duration)).build());
                api.getUserManager().saveUser(user);
            });
        }
    }
}
