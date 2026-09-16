package dev.n1xend.secureauth.config;

import dev.n1xend.secureauth.webhook.WebhookTarget;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.plugin.java.JavaPlugin;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Loads, validates, and provides typed access to {@code config.yml}.
 *
 * <p>All config values are cached after load. Call {@link #reload()} to re-read from disk.
 * Supports hot-reload: never recreates the database pool.
 */
public final class PluginConfig {

    private static final int CURRENT_VERSION = 3;

    private final JavaPlugin plugin;
    private final Logger log;
    private FileConfiguration cfg;

    // Cached typed sub-configs (populated on load/reload)
    private String language;
    private boolean debug;
    private DatabaseConfig databaseConfig;
    private SecurityConfig securityConfig;
    private AntiBotConfig antiBotConfig;
    private TwoFaConfig twoFaConfig;
    private EmailConfig emailConfig;
    private GeoIpConfig geoIpConfig;
    private RateLimitConfig rateLimitConfig;
    private AuthConfig authConfig;
    private List<WebhookTarget> webhookTargets;
    private UpdateCheckerConfig updateCheckerConfig;

    public PluginConfig(JavaPlugin plugin) {
        this.plugin = plugin;
        this.log = plugin.getSLF4JLogger();
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Loads config from disk, saves defaults if missing, and validates all keys.
     *
     * @return {@code true} if config is valid and all fields populated
     */
    public boolean load() {
        plugin.saveDefaultConfig();
        plugin.reloadConfig();
        cfg = plugin.getConfig();
        return validate();
    }

    /**
     * Hot-reload: re-reads config.yml from disk without restarting services.
     * Never recreates the HikariCP pool (§22 standard).
     *
     * @return {@code true} if config is valid after reload
     */
    public boolean reload() {
        plugin.reloadConfig();
        cfg = plugin.getConfig();
        return validate();
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    public String getLanguage() {
        return language;
    }

    public boolean isDebug() {
        return debug;
    }

    public DatabaseConfig getDatabase() {
        return databaseConfig;
    }

    public SecurityConfig getSecurity() {
        return securityConfig;
    }

    public AntiBotConfig getAntiBot() {
        return antiBotConfig;
    }

    public TwoFaConfig getTwoFa() {
        return twoFaConfig;
    }

    public EmailConfig getEmail() {
        return emailConfig;
    }

    public GeoIpConfig getGeoIp() {
        return geoIpConfig;
    }

    public RateLimitConfig getRateLimit() {
        return rateLimitConfig;
    }

    public AuthConfig getAuth() {
        return authConfig;
    }

    public List<WebhookTarget> getWebhooks() {
        return webhookTargets;
    }

    public UpdateCheckerConfig getUpdateChecker() {
        return updateCheckerConfig;
    }

    // ── Private: validation ───────────────────────────────────────────────────

    private boolean validate() {
        List<String> errors = new ArrayList<>();

        int version = cfg.getInt("config-version", 0);
        if (version != CURRENT_VERSION) {
            errors.add("config-version must be " + CURRENT_VERSION + ", got " + version
                    + " — please update your config.yml");
        }

        String lang = cfg.getString("language", "en");
        if (!lang.equals("en") && !lang.equals("ru")) {
            errors.add("language must be 'en' or 'ru', got: " + lang);
        }

        String dbType = cfg.getString("database.type", "sqlite");
        if (!dbType.equals("sqlite") && !dbType.equals("mysql")) {
            errors.add("database.type must be 'sqlite' or 'mysql', got: " + dbType);
        }

        int minPw = cfg.getInt("security.password-min-length", 6);
        int maxPw = cfg.getInt("security.password-max-length", 64);
        if (minPw < 4 || minPw > 32) {
            errors.add("security.password-min-length must be 4–32, got: " + minPw);
        }
        if (maxPw < minPw) {
            errors.add("security.password-max-length must be >= min-length");
        }

        int sessionTtl = cfg.getInt("security.session-timeout-minutes", 30);
        if (sessionTtl < 0) {
            errors.add("security.session-timeout-minutes must be >= 0 (0 = sessions disabled), got: " + sessionTtl);
        }

        if (!errors.isEmpty()) {
            log.error("=== SecureAuth config validation failed ({} error(s)) ===", errors.size());
            errors.forEach(e -> log.error("  • {}", e));
            log.error("=========================================================");
            return false;
        }

        // Everything below is only reached once ALL validation above has passed —
        // this keeps reload() atomic: either every config section updates together,
        // or (on any validation failure) NONE of them do and the previous
        // known-good config remains fully in effect. language/debug used to be
        // assigned eagerly further up, before this check — meaning a reload
        // rejected for an unrelated reason (e.g. a typo in database.type) would
        // still silently apply a language/debug change from the same broken
        // config.yml, leaving the plugin in a partially-reloaded state despite
        // reporting failure.
        this.language = lang;
        this.debug = cfg.getBoolean("debug", false);
        databaseConfig = buildDatabase();
        securityConfig = buildSecurity();
        antiBotConfig = buildAntiBot();
        twoFaConfig = buildTwoFa();
        emailConfig = buildEmail();
        geoIpConfig = buildGeoIp();
        rateLimitConfig = buildRateLimit();
        authConfig = buildAuth();
        webhookTargets = buildWebhooks();
        updateCheckerConfig = new UpdateCheckerConfig(cfg.getBoolean("update-checker.enabled", true));
        return true;
    }

    // ── Private: sub-config builders ──────────────────────────────────────────

    private DatabaseConfig buildDatabase() {
        return new DatabaseConfig(cfg.getString("database.type", "sqlite"),
                cfg.getString("database.mysql.host", "localhost"), cfg.getInt("database.mysql.port", 3306),
                cfg.getString("database.mysql.database", "secureauth"),
                cfg.getString("database.mysql.username", "root"), cfg.getString("database.mysql.password", ""),
                cfg.getInt("database.mysql.pool-size", 10), cfg.getLong("database.mysql.connection-timeout", 30_000),
                cfg.getLong("database.mysql.idle-timeout", 600_000),
                cfg.getLong("database.mysql.max-lifetime", 1_800_000),
                // Default false to stay backward-compatible with existing installs whose
                // MySQL server has no TLS certificate configured. See the startup warning
                // in SecureAuthPlugin for when this actually matters (non-localhost host).
                cfg.getBoolean("database.mysql.use-ssl", false));
    }

    private SecurityConfig buildSecurity() {
        return new SecurityConfig(cfg.getInt("security.argon2.memory", 65536),
                cfg.getInt("security.argon2.iterations", 3), cfg.getInt("security.argon2.parallelism", 4),
                cfg.getInt("security.max-login-attempts", 5), cfg.getInt("security.ban-duration-minutes", 30),
                cfg.getInt("security.session-timeout-minutes", 30), cfg.getBoolean("security.session-ip-binding", true),
                cfg.getInt("security.password-min-length", 6), cfg.getInt("security.password-max-length", 64));
    }

    private AntiBotConfig buildAntiBot() {
        return new AntiBotConfig(cfg.getBoolean("antibot.enabled", true),
                cfg.getInt("antibot.max-connections-per-second", 10), cfg.getInt("antibot.max-pending-logins", 50),
                cfg.getInt("antibot.ip-block-threshold", 10), cfg.getInt("antibot.ip-block-duration-minutes", 60));
    }

    private TwoFaConfig buildTwoFa() {
        return new TwoFaConfig(cfg.getBoolean("two-factor.enabled", true),
                cfg.getString("two-factor.require-for-permission", ""), cfg.getInt("two-factor.backup-codes-count", 8),
                cfg.getString("two-factor.issuer", "SecureAuth"),
                // Default false: sending the raw TOTP secret to a third-party QR
                // image service (api.qrserver.com) leaks it outside the server.
                // Opt-in only, with the tradeoff documented in config comments.
                cfg.getBoolean("two-factor.qr-via-external-service", false));
    }

    private EmailConfig buildEmail() {
        return new EmailConfig(cfg.getBoolean("email.enabled", false),
                cfg.getString("email.smtp.host", "smtp.gmail.com"), cfg.getInt("email.smtp.port", 587),
                cfg.getString("email.smtp.username", ""), cfg.getString("email.smtp.password", ""),
                cfg.getString("email.smtp.from", "noreply@example.com"),
                cfg.getString("email.smtp.from-name", "SecureAuth"), cfg.getBoolean("email.smtp.tls", true),
                cfg.getInt("email.recovery-token-ttl-minutes", 30));
    }

    private GeoIpConfig buildGeoIp() {
        return new GeoIpConfig(cfg.getBoolean("geoip.enabled", false),
                cfg.getString("geoip.database-path", "plugins/SecureAuth/GeoLite2-Country.mmdb"),
                cfg.getStringList("geoip.blocked-countries"), cfg.getStringList("geoip.allowed-countries"));
    }

    private RateLimitConfig buildRateLimit() {
        return new RateLimitConfig(cfg.getInt("rate-limit.register-max", 3),
                cfg.getInt("rate-limit.register-window-seconds", 60), cfg.getInt("rate-limit.login-max", 10),
                cfg.getInt("rate-limit.login-window-seconds", 60), cfg.getInt("rate-limit.totp-max", 5),
                cfg.getInt("rate-limit.totp-window-seconds", 60));
    }

    private AuthConfig buildAuth() {
        return new AuthConfig(cfg.getInt("auth.login-timeout-seconds", 60),
                cfg.getBoolean("auth.blind-before-auth", true), cfg.getBoolean("auth.block-chat", true),
                cfg.getBoolean("auth.block-movement", false));
    }

    private List<WebhookTarget> buildWebhooks() {
        // getMapList returns only entries that are YAML maps (not scalars/lists).
        // This safely skips malformed entries like `webhooks: [events]`.
        var list = cfg.getMapList("webhooks");
        List<WebhookTarget> targets = new ArrayList<>();
        for (var rawEntry : list) {
            try {
                // rawEntry from Bukkit getMapList() is Map<?,?> at compile time;
                // use get() + explicit null fallback to stay cast-free
                Object urlObj = rawEntry.get("url");
                Object enabledRaw = rawEntry.get("enabled");
                Object enabledObj = enabledRaw != null ? enabledRaw : Boolean.TRUE;
                Object evRaw = rawEntry.get("events");

                if (!(urlObj instanceof String url) || url.isBlank())
                    continue;
                boolean enabled = enabledObj instanceof Boolean b ? b
                        : Boolean.parseBoolean(String.valueOf(enabledObj));
                List<String> events = evRaw instanceof List<?> evList
                        ? evList.stream().filter(e -> e instanceof String).map(Object::toString).toList()
                        : List.of();
                targets.add(new WebhookTarget(url, events, enabled));
                log.info("[Webhook] Registered target: {} (events={})", url, events.isEmpty() ? "ALL" : events);
            } catch (Exception e) {
                log.warn("[Webhook] Skipping malformed webhook entry: {}", e.getMessage());
            }
        }
        if (targets.isEmpty() && !cfg.getList("webhooks", Collections.emptyList()).isEmpty()) {
            log.warn("[Webhook] webhooks: section is present but no valid targets were parsed.");
            log.warn(
                    "[Webhook] Correct format: webhooks:\n  - url: \"https://discord.com/api/webhooks/...\"\n    enabled: true\n    events: []");
        }
        return List.copyOf(targets);
    }

    // ── Sub-config records ─────────────────────────────────────────────────────────

    public record DatabaseConfig(String type, String host, int port, String database, String username, String password,
            int poolSize, long connectionTimeout, long idleTimeout, long maxLifetime, boolean useSsl) {

        public boolean isMysql() {
            return "mysql".equalsIgnoreCase(type);
        }

        public boolean isSqlite() {
            return "sqlite".equalsIgnoreCase(type);
        }
    }

    public record SecurityConfig(int argon2Memory, int argon2Iterations, int argon2Parallelism, int maxLoginAttempts,
            int banDurationMinutes, int sessionTimeoutMinutes, boolean sessionIpBinding, int passwordMinLength,
            int passwordMaxLength) {
    }

    public record AntiBotConfig(boolean enabled, int maxConnectionsPerSecond, int maxPendingLogins,
            int ipBlockThreshold, int ipBlockDurationMinutes) {
    }

    public record TwoFaConfig(boolean enabled, String requireForPermission, int backupCodesCount, String issuer,
            boolean qrViaExternalService) {
    }

    public record EmailConfig(boolean enabled, String smtpHost, int smtpPort, String username, String password,
            String from, String fromName, boolean tls, int recoveryTokenTtlMinutes) {
    }

    public record GeoIpConfig(boolean enabled, String databasePath, List<String> blockedCountries,
            List<String> allowedCountries) {
    }

    public record RateLimitConfig(int registerMax, int registerWindowSeconds, int loginMax, int loginWindowSeconds,
            int totpMax, int totpWindowSeconds) {
    }

    public record AuthConfig(int loginTimeoutSeconds, boolean blindBeforeAuth, boolean blockChat,
            boolean blockMovement) {
    }

    public record UpdateCheckerConfig(boolean enabled) {
    }
}
