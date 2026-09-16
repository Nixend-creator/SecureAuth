package dev.n1xend.secureauth.module;

import dev.n1xend.secureauth.SecureAuthPlugin;
import dev.n1xend.secureauth.config.PluginConfig;
import dev.n1xend.secureauth.i18n.LanguageManager;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * Manages hot-reloadable modules.
 *
 * <p>Called by {@code /saadmin reload} to reload config + i18n without server restart.
 */
public final class ModuleManager {

    private final SecureAuthPlugin plugin;
    private final PluginConfig config;
    private final LanguageManager lang;
    private final Logger log;
    private final List<HotReloadableModule> modules = new ArrayList<>();

    public ModuleManager(SecureAuthPlugin plugin, PluginConfig config, LanguageManager lang, Logger log) {
        this.plugin = plugin;
        this.config = config;
        this.lang = lang;
        this.log = log;
    }

    public void registerAll() {
        // Config module
        modules.add(new HotReloadableModule() {
            @Override
            public String name() {
                return "Config";
            }

            @Override
            public ReloadResult reload() {
                long start = System.currentTimeMillis();
                try {
                    boolean ok = config.reload();
                    if (!ok)
                        return ReloadResult.fail(name(), System.currentTimeMillis() - start, "Validation failed");
                    return ReloadResult.ok(name(), System.currentTimeMillis() - start);
                } catch (Exception e) {
                    return ReloadResult.fail(name(), System.currentTimeMillis() - start, e.getMessage());
                }
            }
        });

        // Language module
        modules.add(new HotReloadableModule() {
            @Override
            public String name() {
                return "Language";
            }

            @Override
            public ReloadResult reload() {
                long start = System.currentTimeMillis();
                try {
                    lang.loadAll();
                    return ReloadResult.ok(name(), System.currentTimeMillis() - start);
                } catch (Exception e) {
                    return ReloadResult.fail(name(), System.currentTimeMillis() - start, e.getMessage());
                }
            }
        });

        // Webhook module — shutdown old executor, rebuild with updated targets from config
        modules.add(new HotReloadableModule() {
            @Override
            public String name() {
                return "Webhooks";
            }

            @Override
            public ReloadResult reload() {
                long start = System.currentTimeMillis();
                try {
                    plugin.reloadWebhookService();
                    int count = config.getWebhooks().size();
                    log.info("[Webhook] Reloaded: {} target(s).", count);
                    return ReloadResult.ok(name(), System.currentTimeMillis() - start);
                } catch (Exception e) {
                    return ReloadResult.fail(name(), System.currentTimeMillis() - start, e.getMessage());
                }
            }
        });
    }

    /** Reloads all registered modules in order. */
    public List<ReloadResult> reloadAll() {
        List<ReloadResult> results = new ArrayList<>();
        for (HotReloadableModule module : modules) {
            try {
                ReloadResult result = module.reload();
                results.add(result);
                if (result.success()) {
                    log.info("[Reload] {} OK ({}ms)", result.moduleName(), result.durationMs());
                } else {
                    log.error("[Reload] {} FAILED: {}", result.moduleName(), result.error());
                }
            } catch (Exception e) {
                results.add(ReloadResult.fail(module.name(), 0, e.getMessage()));
                log.error("[Reload] {} threw exception: {}", module.name(), e.getMessage());
            }
        }
        return results;
    }
}
