package dev.n1xend.secureauth.i18n;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.java.JavaPlugin;
import org.slf4j.Logger;

import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Manages plugin translations.
 *
 * <p>Messages are loaded from {@code lang/en.yml} and {@code lang/ru.yml}.
 * All messages use MiniMessage format.
 */
public final class LanguageManager {

    private static final MiniMessage MM = MiniMessage.miniMessage();

    private final JavaPlugin plugin;
    private final String defaultLocale;
    private final Logger log;

    private YamlConfiguration messages;
    private String prefix;

    public LanguageManager(JavaPlugin plugin, String defaultLocale) {
        this.plugin = plugin;
        this.defaultLocale = defaultLocale;
        this.log = plugin.getSLF4JLogger();
    }

    /** Loads language files from disk (or jar defaults). Can be called multiple times (hot-reload). */
    public void loadAll() {
        messages = loadLangFile(defaultLocale);
        prefix = messages.getString("prefix", "<gray>[SecureAuth]</gray> ");
        log.info("[i18n] Loaded language '{}'", defaultLocale);
    }

    private YamlConfiguration loadLangFile(String locale) {
        // Always save the bundled file so new keys are available as defaults.
        // We use the bundled JAR file as the authoritative source of ALL keys.
        // The external file (plugins/SecureAuth/lang/X.yml) overrides individual values,
        // but any key missing from the external file falls back to the bundled version.
        // This ensures updates adding new lang keys always work without manual file deletion.

        // Step 1: Load bundled defaults
        YamlConfiguration defaults = null;
        InputStream bundled = plugin.getResource("lang/" + locale + ".yml");
        if (bundled != null) {
            defaults = YamlConfiguration.loadConfiguration(new InputStreamReader(bundled, StandardCharsets.UTF_8));
        } else if (!locale.equals("en")) {
            log.warn("[i18n] Bundled language '{}' not found, falling back to 'en'", locale);
            return loadLangFile("en");
        }

        // Step 2: Determine if external file needs (re)writing
        File external = new File(plugin.getDataFolder(), "lang/" + locale + ".yml");
        if (external.exists() && defaults != null) {
            // Check lang-version — if outdated, overwrite with bundled to pick up new keys
            YamlConfiguration extCheck = YamlConfiguration.loadConfiguration(external);
            int externalVersion = extCheck.getInt("lang-version", 0);
            int bundledVersion = defaults.getInt("lang-version", 1);
            if (externalVersion < bundledVersion) {
                log.info("[i18n] lang/{}.yml is outdated (v{} < v{}) — refreshing from JAR.", locale, externalVersion,
                        bundledVersion);
                plugin.saveResource("lang/" + locale + ".yml", true); // force overwrite
                log.info("[i18n] Refreshed lang/{}.yml. Edit plugins/SecureAuth/lang/{}.yml to customise.", locale,
                        locale);
            }
        } else if (!external.exists() && defaults != null) {
            plugin.saveResource("lang/" + locale + ".yml", false);
        }

        // Step 3: Load external file (freshly written or pre-existing)
        YamlConfiguration config = null;
        if (external.exists()) {
            config = YamlConfiguration.loadConfiguration(external);
        }

        // Step 4: Apply bundled defaults as fallback for any still-missing keys
        // This covers custom external files that remove some keys.
        if (config != null && defaults != null) {
            config.setDefaults(defaults);
            config.options().copyDefaults(true);
            return config;
        }

        return defaults != null ? defaults : new YamlConfiguration();
    }

    // ── Send helpers ─────────────────────────────────────────────────────────

    /**
     * Sends a message with optional placeholder substitutions.
     * Placeholders are passed as alternating key-value pairs: "key", "value", "key2", "value2"...
     */
    public void send(CommandSender sender, String key, String... placeholders) {
        Component component = build(key, placeholders);
        sender.sendMessage(component);
    }

    /** Builds a Component from a message key with placeholders. */
    public Component build(String key, String... placeholders) {
        String raw = messages.getString(key);
        if (raw == null) {
            log.warn("[i18n] Missing key: '{}'", key);
            raw = "<red>[MISSING: " + key + "]</red>";
        }

        // Prepend prefix for non-kick messages
        String full = prefix + raw;
        full = substitute(full, placeholders);

        return MM.deserialize(full);
    }

    /** Builds a Component for kick messages (no prefix). */
    public Component buildKick(String key, String... placeholders) {
        String raw = messages.getString(key, "[MISSING: " + key + "]");
        raw = substitute(raw, placeholders);
        return MM.deserialize(raw);
    }

    /** Returns a raw string value (for use in non-Adventure contexts like email subjects). */
    public String getRaw(String key, String... placeholders) {
        String raw = messages.getString(key, key);
        raw = substitute(raw, placeholders);
        // Strip MiniMessage tags for plain text output
        return MM.stripTags(raw);
    }

    /**
     * Substitutes {@code {key}} placeholders in {@code template} with their
     * values, keeping every existing lang file's {@code {curly-brace}} syntax
     * unchanged (MiniMessage's own tag resolvers only match {@code <angle-bracket>}
     * syntax, so switching to {@link net.kyori.adventure.text.minimessage.tag.resolver.TagResolver}
     * would have silently broken every placeholder in both lang files).
     *
     * <p><strong>Security:</strong> each value is passed through
     * {@link MiniMessage#escapeTags(String)} <em>before</em> substitution, so
     * any MiniMessage syntax it happens to contain — e.g. a user-supplied email
     * address (validated only as "contains @ and a dot"; nothing stops
     * {@code <}, {@code >}, {@code :}, or {@code '}), a ban reason, an IP, or
     * any other externally-influenced value — renders as inert literal text
     * instead of being interpreted as a real {@code <click:run_command:'...'>}
     * or similar tag. Without this, a crafted value that later reaches an
     * admin's screen (e.g. via an admin-facing view of a player's linked
     * email) could disguise a clickable command as ordinary text and run it
     * as that admin the moment they click it.
     */
    private String substitute(String template, String... placeholders) {
        String result = template;
        for (int i = 0; i + 1 < placeholders.length; i += 2) {
            String safeValue = MM.escapeTags(placeholders[i + 1]);
            result = result.replace("{" + placeholders[i] + "}", safeValue);
        }
        return result;
    }

    public String getDefaultLocale() {
        return defaultLocale;
    }
}
