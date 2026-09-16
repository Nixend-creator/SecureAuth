package dev.n1xend.secureauth.api;

import org.jetbrains.annotations.NotNull;

/**
 * Public API for SecureAuth — safe to use from external plugins.
 *
 * <p>Obtain the API instance via Bukkit's ServicesManager:
 *
 * <pre>{@code
 * var rsp = Bukkit.getServicesManager().getRegistration(SecureAuthApi.class);
 * if (rsp != null) {
 *     SecureAuthApi api = rsp.getProvider();
 * }
 * }</pre>
 *
 * <p><strong>Stability contract:</strong>
 * <ul>
 * <li>Adding a method → minor version bump + default implementation.</li>
 * <li>Changing a signature → major version bump + {@code @Deprecated} for one release.</li>
 * <li>Removing a method → only after 2+ releases with {@code @Deprecated}.</li>
 * </ul>
 */
public interface SecureAuthApi {

    /**
     * Returns the plugin version string (e.g. {@code "1.0.0-rc.1"}).
     * Use this to verify API compatibility at runtime.
     *
     * @return version string, never null
     */
    @NotNull
    String version();

    /**
     * Returns the authentication sub-API.
     *
     * @return auth API, never null
     */
    @NotNull
    AuthApi auth();

    /**
     * Returns the session sub-API.
     *
     * @return session API, never null
     */
    @NotNull
    SessionApi session();

    /**
     * Returns the two-factor authentication sub-API.
     *
     * @return TOTP API, never null
     */
    @NotNull
    TotpApi totp();

    /**
     * Returns the IP ban / anti-bot sub-API.
     *
     * @return anti-bot API, never null
     */
    @NotNull
    AntiBotApi antiBot();
}
