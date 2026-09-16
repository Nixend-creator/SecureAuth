package dev.n1xend.secureauth.api.impl;

import dev.n1xend.secureauth.api.SessionApi;
import dev.n1xend.secureauth.session.SessionService;
import org.jetbrains.annotations.NotNull;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Internal implementation of {@link SessionApi}.
 *
 * <p>Thin delegate — all logic lives in {@link SessionService}. The
 * {@code *Async} overloads run the same underlying blocking call on a
 * virtual thread via {@link CompletableFuture#supplyAsync}/{@code runAsync}
 * with {@link Thread#startVirtualThread} as the executor.
 */
public final class SessionApiImpl implements SessionApi {

    private final SessionService sessions;

    public SessionApiImpl(@NotNull SessionService sessions) {
        this.sessions = sessions;
    }

    @Override
    public boolean hasValidSession(@NotNull UUID uuid, @NotNull String ip) {
        return sessions.hasValidSession(uuid, ip);
    }

    @Override
    public @NotNull CompletableFuture<Boolean> hasValidSessionAsync(@NotNull UUID uuid, @NotNull String ip) {
        return CompletableFuture.supplyAsync(() -> sessions.hasValidSession(uuid, ip), Thread::startVirtualThread);
    }

    @Override
    public void createSession(@NotNull UUID uuid, @NotNull String ip) {
        sessions.create(uuid, ip);
    }

    @Override
    public @NotNull CompletableFuture<Void> createSessionAsync(@NotNull UUID uuid, @NotNull String ip) {
        return CompletableFuture.runAsync(() -> sessions.create(uuid, ip), Thread::startVirtualThread);
    }

    @Override
    public void invalidateSession(@NotNull UUID uuid) {
        sessions.invalidate(uuid);
    }

    @Override
    public @NotNull CompletableFuture<Void> invalidateSessionAsync(@NotNull UUID uuid) {
        return CompletableFuture.runAsync(() -> sessions.invalidate(uuid), Thread::startVirtualThread);
    }
}
