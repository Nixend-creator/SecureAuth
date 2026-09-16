package dev.n1xend.secureauth.module;

/** Result of a module hot-reload operation. */
public record ReloadResult(String moduleName, boolean success, long durationMs, String error) {

    public static ReloadResult ok(String name, long durationMs) {
        return new ReloadResult(name, true, durationMs, null);
    }

    public static ReloadResult fail(String name, long durationMs, String error) {
        return new ReloadResult(name, false, durationMs, error);
    }
}
