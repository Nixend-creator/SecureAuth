package dev.n1xend.secureauth.webhook;

import java.util.List;

/**
 * Configuration for a single Discord webhook endpoint.
 *
 * @param url     Discord webhook URL
 * @param events  whitelist of event names to send; empty = all events
 * @param enabled quick on/off toggle
 */
public record WebhookTarget(String url, List<String> events, boolean enabled) {
}
