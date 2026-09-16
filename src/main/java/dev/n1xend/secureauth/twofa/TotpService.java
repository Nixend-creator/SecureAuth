package dev.n1xend.secureauth.twofa;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.n1xend.secureauth.config.PluginConfig;
import dev.n1xend.secureauth.database.DatabaseManager;
import dev.n1xend.secureauth.database.repository.TotpRepository;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Manages TOTP (Time-based One-Time Password) two-factor authentication.
 *
 * <p>Uses Google Authenticator-compatible TOTP (RFC 6238).
 */
public final class TotpService {

    private static final SecureRandom RNG = new SecureRandom();

    private final TotpRepository repo;
    private final PluginConfig config;
    private final SecretGenerator secretGen = new DefaultSecretGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeGenerator codeGen = new DefaultCodeGenerator();

    /**
     * Verifies a TOTP code against a secret, checking the current period
     * plus one period before and after (±30 s) to handle clock drift.
     * <p>Uses {@link CodeGenerator} directly instead of {@link DefaultCodeVerifier}
     * so we don't depend on a specific method name that varies across library versions.
     *
     * <p><strong>Replay protection:</strong> a code is only valid for its
     * time-bucket the FIRST time it's successfully used. Without this, the
     * same 6-digit code stays valid for its full ~90s window (3 buckets) no
     * matter how many times it's submitted — the classic gap exploited by
     * real-time OTP-relay phishing (a fake login page captures the code the
     * instant a victim types it and immediately replays it to the real
     * server) and by simple shoulder-surfing/screen-recording. Tracking the
     * last successfully-used bucket per account and rejecting anything at or
     * before it is standard practice for any serious TOTP implementation.
     */
    private boolean isValidTotp(UUID uuid, String secret, String code) {
        long currentBucket = timeProvider.getTime() / 30;
        Long lastUsed = lastUsedBucket.getIfPresent(uuid);
        for (long delta = -1; delta <= 1; delta++) {
            long bucket = currentBucket + delta;
            if (lastUsed != null && bucket <= lastUsed)
                continue; // already used or older — reject
            try {
                String expected = codeGen.generate(secret, bucket);
                // Constant-time comparison: a 6-digit code has only 10^6
                // possibilities, so timing side channels are a low-severity
                // concern in practice over a network connection, but this is
                // free defense-in-depth and matches the treatment given to
                // password/session comparisons elsewhere in the plugin.
                if (constantTimeEquals(expected, code)) {
                    lastUsedBucket.put(uuid, bucket);
                    return true;
                }
            } catch (Exception ignored) {
                // malformed secret or generator error — treat as invalid
            }
        }
        return false;
    }

    /** Constant-time string comparison to avoid timing side channels on secret matches. */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null)
            return false;
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    /** Cache of pending 2FA setup (secret not yet confirmed). */
    private final Cache<UUID, String> pendingSecrets = Caffeine.newBuilder().expireAfterWrite(10, TimeUnit.MINUTES)
            .build();

    /**
     * Last successfully-used TOTP time-bucket per account, for replay
     * protection — see {@link #isValidTotp}. A 5-minute TTL is far longer
     * than the ~90s window this needs to span; it just self-cleans for
     * accounts that aren't actively verifying, rather than growing forever.
     */
    private final Cache<UUID, Long> lastUsedBucket = Caffeine.newBuilder().expireAfterWrite(5, TimeUnit.MINUTES)
            .build();

    /**
     * Per-account locks serializing {@link #verifyBackupCode}.
     *
     * <p>Backup codes are meant to be strictly single-use — that's their
     * whole security property. But the check-then-write there is a classic
     * read-modify-write: read the current code list, check in memory whether
     * the submitted code is unused, then write the whole list back marked
     * "USED:". Without serialization, two verification attempts arriving in
     * close succession (e.g. a modified client double-submitting the same
     * command) could both read the list before either writes, both see the
     * code as unused, and both return {@code true} — the same backup code
     * granting two successful uses despite the DB correctly ending up marked
     * "used" afterward. The window is small (no slow hashing involved here,
     * unlike password verification) but real. A per-account lock, rather
     * than a schema change to individually-keyed rows, closes it with
     * minimal risk given how infrequently this path is exercised (at most
     * once per login for an account using a backup code at all).
     * <p>Deliberately a plain, unbounded {@link ConcurrentHashMap} rather
     * than a TTL-based cache (unlike {@link #lastUsedBucket} above): evicting
     * a lock object while another thread might still be {@code synchronized}
     * on it would let two concurrent callers for the SAME account end up
     * locking on two DIFFERENT objects after an eviction/recreate, defeating
     * the lock entirely. Growth here is bounded by the number of distinct
     * player accounts that ever verify a backup code over the server's
     * entire lifetime (not by arbitrary connection attempts, which can be
     * bot-flood-driven and genuinely unbounded) — a negligible, effectively
     * capped memory cost even for a server with tens of thousands of
     * accounts.
     */
    private final ConcurrentHashMap<UUID, Object> backupCodeLocks = new ConcurrentHashMap<>();

    public TotpService(DatabaseManager db, PluginConfig config) {
        this.repo = new TotpRepository(db);
        this.config = config;
    }

    // ── Setup flow ───────────────────────────────────────────────────────────

    /** Generates a new secret for 2FA setup and stores it in pending cache. */
    public TotpSetupData startSetup(UUID uuid, String username) {
        String secret = secretGen.generate();
        pendingSecrets.put(uuid, secret);

        QrData qrData = new QrData.Builder().label(username).secret(secret).issuer(config.getTwoFa().issuer())
                .algorithm(HashingAlgorithm.SHA1).digits(6).period(30).build();

        String otpauthUri = qrData.getUri();
        // SECURITY: only send the secret to a third-party QR image service
        // (api.qrserver.com) if the operator has explicitly opted in. Doing
        // so by default would leak every player's TOTP seed off-server via a
        // plain GET request — visible to that service's access logs, any
        // transparent proxy on the path, and the player's own browser
        // history. Default is manual entry: the raw secret and otpauth URI
        // are always returned below regardless of this setting.
        String qrImageUrl = config.getTwoFa().qrViaExternalService() ? buildQrImageUrl(otpauthUri) : null;

        return new TotpSetupData(secret, otpauthUri, qrImageUrl);
    }

    /** Returns a URL pointing to a 200×200 QR-code image for the given data string. */
    private static String buildQrImageUrl(String data) {
        try {
            String encoded = URLEncoder.encode(data, StandardCharsets.UTF_8);
            return "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=" + encoded;
        } catch (Exception e) {
            return data; // fallback: raw URI
        }
    }

    /** Confirms setup: verifies the code, saves secret + backup codes to DB. */
    public boolean confirmSetup(UUID uuid, String code) {
        String secret = pendingSecrets.getIfPresent(uuid);
        if (secret == null)
            return false;

        if (!isValidTotp(uuid, secret, code))
            return false;
        List<String> backupCodes = generateBackupCodes(config.getTwoFa().backupCodesCount());
        repo.save(uuid, secret, true, backupCodes);
        pendingSecrets.invalidate(uuid);
        return true;
    }

    // ── Verification ─────────────────────────────────────────────────────────

    public boolean isEnabled(UUID uuid) {
        return repo.isEnabled(uuid);
    }

    /** Verifies a TOTP code or backup code. */
    public boolean verify(UUID uuid, String code) {
        TotpData data = repo.find(uuid).orElse(null);
        if (data == null || !data.enabled())
            return false;

        // Check TOTP code (6 digits)
        if (code.matches("\\d{6}")) {
            return isValidTotp(uuid, data.secret(), code);
        }

        // Check backup code
        return verifyBackupCode(uuid, data, code);
    }

    /** Disables 2FA after verifying the current code. */
    public boolean disable(UUID uuid, String code) {
        TotpData data = repo.find(uuid).orElse(null);
        if (data == null || !data.enabled())
            return false;
        if (!isValidTotp(uuid, data.secret(), code))
            return false;
        repo.disable(uuid);
        return true;
    }

    // ── Backup codes ─────────────────────────────────────────────────────────

    public List<String> getBackupCodes(UUID uuid) {
        return repo.find(uuid).map(TotpData::backupCodes).orElse(List.of());
    }

    public List<String> regenerateBackupCodes(UUID uuid) {
        // Same lock as verifyBackupCode() — without it, a backup-code login
        // (verifyBackupCode) and a regenerate (this method) landing in close
        // succession — a completely normal workflow: use a backup code to log
        // in, then immediately regenerate a fresh batch — could race. If the
        // verify's write (marking one old code "USED:") lands AFTER this
        // method's fresh overwrite, it would silently resurrect the entire
        // OLD code list over the new one: the player would believe they have
        // the fresh codes just shown to them, while the account's actual
        // valid codes in the database are the old, mostly-unused set they no
        // longer have a record of — a real risk of a legitimate player
        // getting effectively locked out of backup-code recovery, not just a
        // theoretical concern.
        Object lock = backupCodeLocks.computeIfAbsent(uuid, k -> new Object());
        synchronized (lock) {
            List<String> codes = generateBackupCodes(config.getTwoFa().backupCodesCount());
            repo.updateBackupCodes(uuid, codes);
            return codes;
        }
    }

    private boolean verifyBackupCode(UUID uuid, TotpData staleData, String inputCode) {
        String normalizedInput = inputCode.trim().toUpperCase();
        Object lock = backupCodeLocks.computeIfAbsent(uuid, k -> new Object());
        synchronized (lock) {
            // Re-fetch fresh data INSIDE the lock rather than trusting staleData,
            // which the caller fetched before this lock was acquired. Without
            // this, a second, concurrent call that was waiting on the lock would
            // still be checking its own pre-lock snapshot once it gets in —
            // synchronizing the write alone doesn't help if the read it's
            // deciding from is already stale.
            TotpData data = repo.find(uuid).orElse(staleData);
            if (data == null)
                return false;
            List<String> codes = new ArrayList<>(data.backupCodes());
            // Backup codes stored as "CODE" or "USED:CODE"
            for (int i = 0; i < codes.size(); i++) {
                String stored = codes.get(i);
                if (!stored.startsWith("USED:") && constantTimeEquals(stored.toUpperCase(), normalizedInput)) {
                    codes.set(i, "USED:" + stored);
                    repo.updateBackupCodes(uuid, codes);
                    return true;
                }
            }
            return false;
        }
    }

    private List<String> generateBackupCodes(int count) {
        List<String> codes = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            codes.add(String.format("%04d-%04d", RNG.nextInt(10000), RNG.nextInt(10000)));
        }
        return codes;
    }

    // ── Inner types ──────────────────────────────────────────────────────────

    public record TotpSetupData(String secret, String qrUri, String qrImageUrl) {
    }
}
