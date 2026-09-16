package dev.n1xend.secureauth.player;

import java.util.UUID;

/**
 * Immutable snapshot of a player's authentication record (from database).
 */
public record PlayerData(UUID uuid, String username, String passwordHash, String email, String ipAddress,
        String registeredAt, String lastLoginAt, String lastLoginIp) {
}
