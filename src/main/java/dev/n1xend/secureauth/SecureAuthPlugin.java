package dev.n1xend.secureauth;

import dev.n1xend.secureauth.api.SecureAuthApi;
import dev.n1xend.secureauth.api.impl.AntiBotApiImpl;
import dev.n1xend.secureauth.api.impl.AuthApiImpl;
import dev.n1xend.secureauth.api.impl.SecureAuthApiImpl;
import dev.n1xend.secureauth.api.impl.SessionApiImpl;
import dev.n1xend.secureauth.api.impl.TotpApiImpl;
import dev.n1xend.secureauth.antibot.AntiBotService;
import dev.n1xend.secureauth.command.AdminCommand;
import dev.n1xend.secureauth.command.AuthCommand;
import dev.n1xend.secureauth.config.PluginConfig;
import dev.n1xend.secureauth.database.DatabaseManager;
import dev.n1xend.secureauth.debug.DebugLogger;
import dev.n1xend.secureauth.email.EmailService;
import dev.n1xend.secureauth.geoip.GeoIpService;
import dev.n1xend.secureauth.i18n.LanguageManager;
import dev.n1xend.secureauth.integration.LuckPermsIntegration;
import dev.n1xend.secureauth.integration.VaultIntegration;
import dev.n1xend.secureauth.listener.AuthListener;
import dev.n1xend.secureauth.listener.ProtectionListener;
import dev.n1xend.secureauth.module.ModuleManager;
import dev.n1xend.secureauth.papi.SecureAuthExpansion;
import dev.n1xend.secureauth.player.PlayerDataService;
import dev.n1xend.secureauth.security.PasswordService;
import dev.n1xend.secureauth.session.SessionService;
import dev.n1xend.secureauth.shutdown.ShutdownManager;
import dev.n1xend.secureauth.twofa.TotpService;
import dev.n1xend.secureauth.util.StartupTimer;
import dev.n1xend.secureauth.audit.AuditLogService;
import dev.n1xend.secureauth.update.UpdateChecker;
import dev.n1xend.secureauth.webhook.WebhookService;
import org.bukkit.plugin.ServicePriority;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.concurrent.Executor;

/**
 * SecureAuth — Modern authentication plugin for Paper 1.21.1+.
 *
 * <p>Entry point. Wires all services via constructor injection and registers
 * commands, listeners, and the public API via Bukkit's ServicesManager.
 */
public final class SecureAuthPlugin extends JavaPlugin {

    // Services — injected in onEnable(), used in onDisable() via ShutdownManager
    private PluginConfig pluginConfig;
    private LanguageManager lang;
    private DatabaseManager database;
    private PasswordService passwordService;
    private SessionService sessionService;
    private PlayerDataService playerDataService;
    private TotpService totpService;
    private EmailService emailService;
    private GeoIpService geoIpService;
    private AntiBotService antiBotService;
    private ModuleManager moduleManager;
    private DebugLogger debugLogger;
    private VaultIntegration vault;
    private LuckPermsIntegration luckPerms;
    private ShutdownManager shutdownManager;
    private AuthApiImpl authApiImpl;
    private WebhookService webhookService;
    private AuditLogService auditLogService;
    private UpdateChecker updateChecker;

    /** Executes tasks on the main server thread. */
    private Executor mainThreadExecutor;

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    @Override
    public void onEnable() {
        StartupTimer timer = new StartupTimer(getSLF4JLogger());

        mainThreadExecutor = task -> getServer().getScheduler().runTask(this, task);

        // Config
        timer.stage("Config");
        pluginConfig = new PluginConfig(this);
        if (!pluginConfig.load()) {
            getSLF4JLogger().error("[SecureAuth] Config validation failed — disabling.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        timer.end("Config");

        // Debug logger (zero-cost when disabled)
        debugLogger = new DebugLogger(getSLF4JLogger(), pluginConfig.isDebug());

        // Language
        timer.stage("Language");
        lang = new LanguageManager(this, pluginConfig.getLanguage());
        lang.loadAll();
        timer.end("Language");

        // Database
        timer.stage("Database");
        database = new DatabaseManager(this, pluginConfig, getSLF4JLogger());
        if (!database.connect()) {
            getSLF4JLogger().error("[SecureAuth] Database connection failed — disabling.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        timer.end("Database");

        timer.stage("Migrations");
        database.migrate();
        timer.end("Migrations");

        // Audit log
        auditLogService = new AuditLogService(database, getSLF4JLogger());

        // Core services — constructor injection, explicit dependency order
        timer.stage("Services");
        passwordService = new PasswordService(pluginConfig);
        sessionService = new SessionService(database, pluginConfig);
        playerDataService = new PlayerDataService(database, sessionService, getSLF4JLogger());
        totpService = new TotpService(database, pluginConfig);
        emailService = new EmailService(pluginConfig, getSLF4JLogger());
        geoIpService = new GeoIpService(pluginConfig, getSLF4JLogger());
        antiBotService = new AntiBotService(pluginConfig, getSLF4JLogger());
        antiBotService.setDatabase(database);
        timer.end("Services");

        // Soft-depend integrations
        timer.stage("Integrations");
        vault = new VaultIntegration(this, getSLF4JLogger());
        vault.setup();
        luckPerms = new LuckPermsIntegration(this, getSLF4JLogger());
        luckPerms.setup();
        timer.end("Integrations");

        // Webhooks
        webhookService = new WebhookService(pluginConfig.getWebhooks(), getSLF4JLogger());
        var wh = pluginConfig.getWebhooks();
        if (!wh.isEmpty()) {
            getSLF4JLogger().info("[SecureAuth] Webhooks: {} target(s) configured.", wh.size());
            for (var t : wh) {
                getSLF4JLogger().info("[SecureAuth]   → {} (enabled={}, events={})",
                        t.url().length() > 60 ? t.url().substring(0, 60) + "..." : t.url(), t.enabled(),
                        t.events().isEmpty() ? "ALL" : t.events());
            }
        } else {
            getSLF4JLogger().info("[SecureAuth] Webhooks: not configured (webhooks: [] in config).");
        }

        // PlaceholderAPI expansion (soft-depend)
        if (getServer().getPluginManager().getPlugin("PlaceholderAPI") != null) {
            new SecureAuthExpansion(playerDataService, totpService, sessionService).register();
            getSLF4JLogger().info("[SecureAuth] PlaceholderAPI expansion registered.");
        }

        // Hot-reload modules
        timer.stage("Modules");
        moduleManager = new ModuleManager(this, pluginConfig, lang, getSLF4JLogger());
        moduleManager.registerAll();
        timer.end("Modules");

        // Commands
        timer.stage("Commands");
        registerCommands();
        timer.end("Commands");

        // Event listeners
        timer.stage("Listeners");
        registerListeners();
        timer.end("Listeners");

        // Graceful shutdown manager
        shutdownManager = new ShutdownManager(playerDataService, sessionService, database, getSLF4JLogger());

        // Public API — register via ServicesManager (Paper Plugin Standards §20)
        authApiImpl = new AuthApiImpl(playerDataService, sessionService, this);
        SecureAuthApi api = new SecureAuthApiImpl(getPluginMeta().getVersion(), authApiImpl,
                new SessionApiImpl(sessionService), new TotpApiImpl(totpService), new AntiBotApiImpl(antiBotService));
        getServer().getServicesManager().register(SecureAuthApi.class, api, this, ServicePriority.Normal);
        getSLF4JLogger().info("[SecureAuth] Public API registered via ServicesManager.");

        timer.printSummary();

        // Update checker — runs once asynchronously, never blocks startup
        updateChecker = new UpdateChecker(getPluginMeta().getVersion(), getSLF4JLogger());
        if (pluginConfig.getUpdateChecker().enabled()) {
            updateChecker.checkAsync(result -> getSLF4JLogger().warn("[SecureAuth] ★ Update available: v{} → v{} | {}",
                    result.currentVersion(), result.latestVersion(), result.releaseUrl()));
        }

        getSLF4JLogger().info("[SecureAuth] Version {} enabled.", getPluginMeta().getVersion());
    }

    @Override
    public void onDisable() {
        getSLF4JLogger().info("[SecureAuth] Shutting down...");
        if (webhookService != null)
            webhookService.shutdown();
        if (shutdownManager != null) {
            shutdownManager.shutdown();
        }
        getSLF4JLogger().info("[SecureAuth] Disabled.");
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private void registerCommands() {
        var authCmd = new AuthCommand(this, lang, pluginConfig, playerDataService, passwordService, sessionService,
                totpService, emailService);
        var adminCmd = new AdminCommand(this, lang, pluginConfig, playerDataService, moduleManager, antiBotService,
                debugLogger);

        var cmdMap = getServer().getCommandMap();
        cmdMap.register("secureauth", authCmd.registerLogin());
        cmdMap.register("secureauth", authCmd.registerRegister());
        cmdMap.register("secureauth", authCmd.registerLogout());
        cmdMap.register("secureauth", authCmd.registerChangePassword());
        cmdMap.register("secureauth", authCmd.registerTwoFa());
        cmdMap.register("secureauth", authCmd.registerRecover());
        cmdMap.register("secureauth", adminCmd.build());
    }

    private void registerListeners() {
        var pm = getServer().getPluginManager();
        pm.registerEvents(new AuthListener(this, lang, pluginConfig, playerDataService, sessionService, antiBotService,
                geoIpService), this);
        pm.registerEvents(new ProtectionListener(playerDataService, lang), this);
    }

    // ── Public accessors (for other classes and API) ──────────────────────────

    public PluginConfig getPluginConfig() {
        return pluginConfig;
    }

    public LanguageManager getLang() {
        return lang;
    }

    public DatabaseManager getDatabase() {
        return database;
    }

    public PasswordService getPasswordService() {
        return passwordService;
    }

    public PlayerDataService getPlayerDataService() {
        return playerDataService;
    }

    public SessionService getSessionService() {
        return sessionService;
    }

    public TotpService getTotpService() {
        return totpService;
    }

    public AntiBotService getAntiBotService() {
        return antiBotService;
    }

    public DebugLogger getDebugLogger() {
        return debugLogger;
    }

    public VaultIntegration getVault() {
        return vault;
    }

    public LuckPermsIntegration getLuckPerms() {
        return luckPerms;
    }

    public Executor getMainThreadExecutor() {
        return mainThreadExecutor;
    }

    public AuthApiImpl getAuthApiImpl() {
        return authApiImpl;
    }

    public WebhookService getWebhookService() {
        return webhookService;
    }

    /**
     * Shuts down the current WebhookService executor and creates a new one
     * with targets freshly read from config. Called by {@link dev.n1xend.secureauth.module.ModuleManager}
     * during {@code /saadmin reload}.
     */
    public UpdateChecker getUpdateChecker() {
        return updateChecker;
    }

    public void reloadWebhookService() {
        if (webhookService != null)
            webhookService.shutdown();
        webhookService = new WebhookService(pluginConfig.getWebhooks(), getSLF4JLogger());
    }

    public AuditLogService getAuditLogService() {
        return auditLogService;
    }
}
