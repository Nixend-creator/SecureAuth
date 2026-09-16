package dev.n1xend.secureauth.webhook;

import org.slf4j.Logger;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Sends Discord webhook notifications for auth events.
 *
 * <p>Uses Discord's rich Embed format — color-coded by event type,
 * with player name, UUID, and IP fields.
 *
 * <p>All HTTP I/O runs on virtual threads — zero main-thread blocking.
 * Failures are logged as WARN and never propagate to callers.
 */
public final class WebhookService {

    /** Auth events that trigger webhook notifications. */
    public enum Event {
        REGISTER("✅ Регистрация", 0x57F287, "зарегистрировался на сервере"),
        LOGIN("🔑 Авторизация", 0x5865F2, "вошёл в аккаунт"),
        SESSION_RESTORE("🔄 Зашёл на сервер", 0x57F287, "зашёл на сервер (сессия восстановлена)"),
        DISCONNECT("📴 Отключился", 0x99AAB5, "отключился от сервера"),
        LOGOUT("🚪 Вышел из аккаунта", 0x99AAB5, "вышел из аккаунта командой"),
        LOGIN_FAIL("⚠️ Неудачная попытка", 0xED4245, "неудачная попытка входа"),
        IP_BAN("🔨 IP заблокирован", 0xED4245, "IP заблокирован AntiBot"),
        TOTP_ENABLE("🛡️ 2FA включена", 0x57F287, "включил двухфакторную аутентификацию"),
        TOTP_DISABLE("🔓 2FA отключена", 0xFEE75C, "отключил двухфакторную аутентификацию");

        public final String title;
        public final int color; // Discord embed color (decimal)
        public final String verb; // human-readable action description

        Event(String title, int color, String verb) {
            this.title = title;
            this.color = color;
            this.verb = verb;
        }
    }

    private final List<WebhookTarget> targets;
    private final Logger log;
    private final String version;
    private final ExecutorService executor = Executors
            .newThreadPerTaskExecutor(Thread.ofVirtual().name("sa-webhook-", 0).factory());

    public WebhookService(List<WebhookTarget> targets, String version, Logger log) {
        this.targets = List.copyOf(targets);
        this.version = version;
        this.log = log;
    }

    /**
     * Fires webhooks for an event asynchronously. Returns immediately.
     * Never throws — all errors are logged as WARN.
     */
    public void fireAsync(Event event, String playerName, UUID uuid, String ip) {
        if (targets.isEmpty())
            return;
        executor.submit(() -> {
            for (WebhookTarget target : targets) {
                if (!target.enabled())
                    continue;
                if (!target.events().isEmpty()
                        // Case-insensitive: a config with events: ["login"] (natural to
                        // type in YAML) would otherwise silently match nothing against
                        // event.name() == "LOGIN" — no error logged, webhooks for that
                        // event just never fire, and nothing hints at why.
                        && target.events().stream().noneMatch(e -> e.equalsIgnoreCase(event.name())))
                    continue;
                try {
                    post(target.url(), buildEmbed(event, playerName, uuid, ip));
                    log.info("[Webhook] {} sent to {}", event.name(), maskWebhookUrl(target.url()));
                } catch (Exception e) {
                    log.warn("[Webhook] {} failed for {}: {}", event.name(), maskWebhookUrl(target.url()),
                            e.getMessage());
                }
            }
        });
    }

    /** Graceful shutdown — waits up to 5 s for in-flight requests. */
    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    // ── Discord Embed builder ────────────────────────────────────────────────

    /**
     * Builds a Discord webhook payload with a single rich Embed.
     *
     * <p>Color is event-specific. Fields: Player, UUID, IP.
     * See: https://discord.com/developers/docs/resources/channel#embed-object
     */
    /**
     * Masks the credential portion of a webhook URL before it's ever logged.
     *
     * <p>For Discord (and most other) webhook URLs, the URL itself IS the
     * bearer credential — {@code https://discord.com/api/webhooks/{id}/{token}}
     * — anyone who obtains the full URL can post to that channel as the
     * webhook. Logging it in full on every send would leak that credential
     * into the console and {@code logs/latest.log} exactly like the plaintext
     * password issue this project already fixed for {@code /login} — same
     * category of bug, different feature. Only the last path segment (the
     * token) is masked; the host and webhook ID stay visible for debugging
     * which target sent/failed.
     */
    private static String maskWebhookUrl(String url) {
        int lastSlash = url.lastIndexOf('/');
        if (lastSlash < 0 || lastSlash == url.length() - 1)
            return url;
        return url.substring(0, lastSlash + 1) + "***";
    }

    private String buildEmbed(Event event, String player, UUID uuid, String ip) {
        return """
                {
                  "embeds": [{
                    "title": "%s",
                    "description": "**%s** %s",
                    "color": %d,
                    "fields": [
                      { "name": "UUID", "value": "`%s`", "inline": false },
                      { "name": "IP",   "value": "`%s`", "inline": true }
                    ],
                    "footer": { "text": "SecureAuth" },
                    "timestamp": "%s"
                  }]
                }""".formatted(esc(event.title), esc(player), esc(event.verb), event.color, esc(uuid.toString()),
                esc(ip), Instant.now().toString());
    }

    // ── HTTP ─────────────────────────────────────────────────────────────────

    private void post(String url, String json) throws IOException {
        var con = (HttpURLConnection) URI.create(url).toURL().openConnection();
        try {
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            con.setRequestProperty("User-Agent", "SecureAuth/" + version);
            con.setConnectTimeout(5_000);
            con.setReadTimeout(5_000);
            con.setDoOutput(true);
            try (OutputStream os = con.getOutputStream()) {
                os.write(json.getBytes(StandardCharsets.UTF_8));
            }
            int code = con.getResponseCode();
            if (code < 200 || code >= 300) {
                throw new IOException("HTTP " + code);
            }
        } finally {
            con.disconnect();
        }
    }

    /** Minimal JSON string escaping. */
    private static String esc(String s) {
        if (s == null)
            return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t",
                "\\t");
    }
}
