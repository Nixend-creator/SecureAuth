package dev.n1xend.secureauth.api.impl;

import dev.n1xend.secureauth.api.AntiBotApi;
import dev.n1xend.secureauth.api.AuthApi;
import dev.n1xend.secureauth.api.SecureAuthApi;
import dev.n1xend.secureauth.api.SessionApi;
import dev.n1xend.secureauth.api.TotpApi;
import org.jetbrains.annotations.NotNull;

/**
 * Internal implementation of {@link SecureAuthApi}.
 *
 * <p>Constructed once in {@code SecureAuthPlugin.onEnable()} and registered
 * via {@code ServicesManager}. External plugins never reference this class
 * directly — they always use the interface.
 */
public final class SecureAuthApiImpl implements SecureAuthApi {

    private final String version;
    private final AuthApi auth;
    private final SessionApi session;
    private final TotpApi totp;
    private final AntiBotApi antiBot;

    public SecureAuthApiImpl(@NotNull String version, @NotNull AuthApi auth, @NotNull SessionApi session,
            @NotNull TotpApi totp, @NotNull AntiBotApi antiBot) {
        this.version = version;
        this.auth = auth;
        this.session = session;
        this.totp = totp;
        this.antiBot = antiBot;
    }

    @Override
    public @NotNull String version() {
        return version;
    }

    @Override
    public @NotNull AuthApi auth() {
        return auth;
    }

    @Override
    public @NotNull SessionApi session() {
        return session;
    }

    @Override
    public @NotNull TotpApi totp() {
        return totp;
    }

    @Override
    public @NotNull AntiBotApi antiBot() {
        return antiBot;
    }
}
