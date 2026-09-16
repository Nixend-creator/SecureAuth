package dev.n1xend.secureauth.security;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import dev.n1xend.secureauth.config.PluginConfig;

/**
 * Handles password hashing and verification using Argon2id.
 *
 * <p>Argon2id is the recommended password hashing algorithm (RFC 9106).
 * Parameters are loaded from config and can be tuned for the server hardware.
 */
public final class PasswordService {

    private final Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
    private final PluginConfig config;

    public PasswordService(PluginConfig config) {
        this.config = config;
    }

    /**
     * Hashes a password using Argon2id.
     *
     * @param password plaintext password (char[] to allow zeroing)
     * @return Argon2id hash string
     */
    public String hash(char[] password) {
        PluginConfig.SecurityConfig sc = config.getSecurity();
        return argon2.hash(sc.argon2Iterations(), sc.argon2Memory(), sc.argon2Parallelism(), password);
    }

    /** Convenience overload accepting String. The char[] variant is preferred for security. */
    public String hash(String password) {
        return hash(password.toCharArray());
    }

    /**
     * Verifies a password against a stored hash.
     *
     * @param hash     stored Argon2id hash
     * @param password plaintext candidate
     * @return {@code true} if password matches
     */
    public boolean verify(String hash, char[] password) {
        return argon2.verify(hash, password);
    }

    public boolean verify(String hash, String password) {
        return verify(hash, password.toCharArray());
    }

    /**
     * Validates password against policy from config.
     *
     * @return null if valid, error key if invalid
     */
    public String validate(String password) {
        PluginConfig.SecurityConfig sc = config.getSecurity();
        if (password.length() < sc.passwordMinLength())
            return "register.password-too-short";
        if (password.length() > sc.passwordMaxLength())
            return "register.password-too-long";
        return null;
    }
}
