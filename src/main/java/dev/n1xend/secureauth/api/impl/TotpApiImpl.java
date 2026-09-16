package dev.n1xend.secureauth.api.impl;

import dev.n1xend.secureauth.api.TotpApi;
import dev.n1xend.secureauth.twofa.TotpService;
import org.jetbrains.annotations.NotNull;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Internal implementation of {@link TotpApi}.
 *
 * <p>Both methods perform database reads and therefore run on virtual threads,
 * returning {@link CompletableFuture} to the caller.
 */
public final class TotpApiImpl implements TotpApi {

    private final TotpService totp;

    public TotpApiImpl(@NotNull TotpService totp) {
        this.totp = totp;
    }

    @Override
    public @NotNull CompletableFuture<Boolean> isEnabled(@NotNull UUID uuid) {
        return CompletableFuture.supplyAsync(() -> totp.isEnabled(uuid), Thread::startVirtualThread);
    }

    @Override
    public @NotNull CompletableFuture<Boolean> verify(@NotNull UUID uuid, @NotNull String code) {
        return CompletableFuture.supplyAsync(() -> totp.verify(uuid, code), Thread::startVirtualThread);
    }
}
