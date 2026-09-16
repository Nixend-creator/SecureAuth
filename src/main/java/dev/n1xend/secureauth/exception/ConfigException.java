package dev.n1xend.secureauth.exception;

public final class ConfigException extends SecureAuthException {
    private final String key;

    public ConfigException(String key, String message) {
        super("Config key '" + key + "': " + message);
        this.key = key;
    }

    public String getKey() {
        return key;
    }
}
