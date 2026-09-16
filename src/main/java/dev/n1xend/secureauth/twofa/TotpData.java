package dev.n1xend.secureauth.twofa;

import java.util.List;
import java.util.UUID;

/** Immutable TOTP configuration for a player. */
public record TotpData(UUID uuid, String secret, boolean enabled, List<String> backupCodes) {
}
