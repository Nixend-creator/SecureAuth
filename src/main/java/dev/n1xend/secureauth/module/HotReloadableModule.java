package dev.n1xend.secureauth.module;

/** Interface for modules that support hot-reload without server restart. */
public interface HotReloadableModule {

    String name();

    /**
     * Reloads this module.
     *
     * <p><strong>MUST NOT</strong>: recreate HikariCP pool, unregister Bukkit listeners,
     * reload player data for online players.
     * <p><strong>CAN</strong>: reload config values, i18n strings, Caffeine cache config,
     * debug flags, feature flags.
     *
     * @return reload result with timing and status
     */
    ReloadResult reload();
}
