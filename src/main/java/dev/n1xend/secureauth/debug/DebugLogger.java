package dev.n1xend.secureauth.debug;

import org.slf4j.Logger;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Zero-cost debug logger — checks a flag before formatting the message.
 *
 * <p>Unlike SLF4J's built-in debug level, this flag can be toggled at runtime
 * via {@code /saadmin debug ON|OFF} without reloading the plugin.
 */
public final class DebugLogger {

    private final Logger log;
    private final AtomicBoolean enabled;

    public DebugLogger(Logger log, boolean initiallyEnabled) {
        this.log = log;
        this.enabled = new AtomicBoolean(initiallyEnabled);
    }

    public void log(String format, Object... args) {
        if (enabled.get()) {
            log.info("[DEBUG] " + format, args);
        }
    }

    public void enable() {
        enabled.set(true);
    }

    public void disable() {
        enabled.set(false);
    }

    public void toggle() {
        enabled.set(!enabled.get());
    }

    public boolean isEnabled() {
        return enabled.get();
    }
}
