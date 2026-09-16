package dev.n1xend.secureauth.api.impl;

import dev.n1xend.secureauth.api.AuthApi;
import dev.n1xend.secureauth.player.AuthState;
import dev.n1xend.secureauth.player.PlayerDataService;
import dev.n1xend.secureauth.session.SessionService;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import java.util.concurrent.Executor;
import org.jetbrains.annotations.NotNull;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Internal implementation of {@link AuthApi}.
 *
 * <p>Listeners are stored in a {@link CopyOnWriteArrayList} so iteration during
 * the fire-loop is safe even if a listener removes itself inside the callback.
 */
public final class AuthApiImpl implements AuthApi {

    private final PlayerDataService playerData;
    private final SessionService sessions;
    private final Executor mainThreadExecutor;
    private final org.bukkit.plugin.Plugin plugin;

    /**
     * Thread-safe listener registry. CopyOnWriteArrayList is optimal for
     * read-heavy workloads with infrequent add/remove (typical plugin usage).
     */
    private final List<AuthStateListener> listeners = new CopyOnWriteArrayList<>();

    public AuthApiImpl(@NotNull PlayerDataService playerData, @NotNull SessionService sessions,
            @NotNull org.bukkit.plugin.Plugin plugin, @NotNull Executor mainThreadExecutor) {
        this.playerData = playerData;
        this.sessions = sessions;
        this.plugin = plugin;
        this.mainThreadExecutor = mainThreadExecutor;
    }

    @Override
    public boolean isAuthenticated(@NotNull UUID uuid) {
        return playerData.isAuthenticated(uuid);
    }

    @Override
    public @NotNull CompletableFuture<Boolean> isRegistered(@NotNull UUID uuid) {
        return CompletableFuture.supplyAsync(() -> playerData.getData(uuid).isPresent(), Thread::startVirtualThread);
    }

    @Override
    public @NotNull Optional<AuthSnapshot> getSnapshot(@NotNull UUID uuid) {
        AuthState state = playerData.getAuthState(uuid);
        if (state == null)
            return Optional.empty();
        return Optional
                .of(new AuthSnapshot(uuid, mapStage(state.getStage()), state.getFailedAttempts(), state.getJoinedAt()));
    }

    @Override
    public void forceAuthenticate(@NotNull UUID uuid) {
        Player player = Bukkit.getPlayer(uuid);
        if (player == null) {
            throw new IllegalArgumentException("Player " + uuid + " is not online");
        }
        AuthState state = playerData.getAuthState(uuid);
        Stage previous = mapStage(state.getStage());
        state.markAuthenticated();
        mainThreadExecutor.execute(() -> player.removePotionEffect(org.bukkit.potion.PotionEffectType.BLINDNESS));
        // Use loginIp from AuthState (set in onPlayerLogin from getRealAddress) for consistency.
        String ip = state.getLoginIp();
        // sessions.create is a blocking DB write — run on a virtual thread.
        Thread.startVirtualThread(() -> sessions.create(uuid, ip));
        fireListeners(uuid, previous, Stage.AUTHENTICATED);
    }

    @Override
    public void forceLogout(@NotNull UUID uuid) {
        Player player = Bukkit.getPlayer(uuid);
        if (player == null) {
            throw new IllegalArgumentException("Player " + uuid + " is not online");
        }
        AuthState state = playerData.getAuthState(uuid);
        Stage previous = mapStage(state.getStage());
        state.markPending();
        sessions.invalidate(uuid);
        fireListeners(uuid, previous, Stage.PENDING);
    }

    @Override
    public void addAuthListener(@NotNull AuthStateListener listener) {
        listeners.add(listener);
    }

    @Override
    public void removeAuthListener(@NotNull AuthStateListener listener) {
        listeners.remove(listener);
    }

    /**
     * Fires all registered listeners on the main thread.
     * Called internally whenever auth state changes via the API.
     */
    public void fireListeners(@NotNull UUID uuid, @NotNull Stage previous, @NotNull Stage current) {
        if (listeners.isEmpty())
            return;
        // Always dispatch on main thread — listeners may call Bukkit API
        plugin.getServer().getScheduler().runTask(plugin, () -> {
            for (AuthStateListener l : listeners) {
                try {
                    l.onAuthStateChanged(uuid, previous, current);
                } catch (Exception e) {
                    plugin.getSLF4JLogger().error("[API] AuthStateListener threw an exception: {}", e.getMessage(), e);
                }
            }
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stage mapStage(@NotNull AuthState.Stage internal) {
        return switch (internal) {
            case PENDING -> Stage.PENDING;
            case AWAITING_2FA -> Stage.AWAITING_2FA;
            case AUTHENTICATED -> Stage.AUTHENTICATED;
        };
    }
}
