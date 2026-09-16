package dev.n1xend.secureauth.api.impl;

import dev.n1xend.secureauth.antibot.AntiBotService;
import dev.n1xend.secureauth.api.AntiBotApi;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.time.LocalDateTime;
import java.util.concurrent.CompletableFuture;

/**
 * Internal implementation of {@link AntiBotApi}.
 *
 * <p>Delegates all operations to {@link AntiBotService}.
 * Ban state is backed by Caffeine cache + database; reads hit the cache first.
 * The {@code *Async} overloads run the same underlying (potentially blocking)
 * call on a virtual thread via {@link CompletableFuture}.
 */
public final class AntiBotApiImpl implements AntiBotApi {

    private final AntiBotService antiBot;

    public AntiBotApiImpl(@NotNull AntiBotService antiBot) {
        this.antiBot = antiBot;
    }

    @Override
    public boolean isBanned(@NotNull String ip) {
        return antiBot.isBanned(ip);
    }

    @Override
    public @NotNull CompletableFuture<Boolean> isBannedAsync(@NotNull String ip) {
        return CompletableFuture.supplyAsync(() -> antiBot.isBanned(ip), Thread::startVirtualThread);
    }

    @Override
    public void banIp(@NotNull String ip, @NotNull String reason, @Nullable LocalDateTime expiresAt) {
        antiBot.banIp(ip, reason, expiresAt);
    }

    @Override
    public @NotNull CompletableFuture<Void> banIpAsync(@NotNull String ip, @NotNull String reason,
            @Nullable LocalDateTime expiresAt) {
        return CompletableFuture.runAsync(() -> antiBot.banIp(ip, reason, expiresAt), Thread::startVirtualThread);
    }

    @Override
    public void unbanIp(@NotNull String ip) {
        antiBot.unbanIp(ip);
    }

    @Override
    public @NotNull CompletableFuture<Void> unbanIpAsync(@NotNull String ip) {
        return CompletableFuture.runAsync(() -> antiBot.unbanIp(ip), Thread::startVirtualThread);
    }

    @Override
    public int getPendingLogins() {
        return antiBot.getPendingLogins();
    }
}
