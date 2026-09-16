package dev.n1xend.secureauth.update;

import org.slf4j.Logger;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Checks for new SecureAuth releases on GitHub Releases API.
 *
 * <p>Runs on a virtual thread — zero main-thread blocking.
 * Enable/disable via {@code update-checker.enabled} in {@code config.yml}.
 *
 * <p>GitHub unauthenticated rate-limit: 60 requests/hour per IP — checking
 * once on startup is well within limits.
 */
public final class UpdateChecker {

    private static final String API_URL = "https://api.github.com/repos/Nixend-creator/SecureAuth/releases/latest";
    private static final String RELEASES_URL = "https://github.com/Nixend-creator/SecureAuth/releases";

    // Minimal JSON field extraction — no external JSON library required
    private static final Pattern TAG_PATTERN = Pattern.compile("\"tag_name\"\\s*:\\s*\"v?([^\"]+)\"");
    private static final Pattern HTML_URL_PATTERN = Pattern.compile("\"html_url\"\\s*:\\s*\"([^\"]+)\"");

    private final String currentVersion;
    private final Logger log;

    public UpdateChecker(String currentVersion, Logger log) {
        this.currentVersion = currentVersion;
        this.log = log;
    }

    /**
     * Checks for updates asynchronously on a virtual thread.
     *
     * @param onResult called (still on the virtual thread) if a newer version is found
     */
    public void checkAsync(Consumer<UpdateResult> onResult) {
        Thread.startVirtualThread(() -> {
            try {
                fetchLatest().ifPresent(result -> {
                    if (result.isNewer()) {
                        log.info("[UpdateChecker] ★ New version available: {} → {} | {}", currentVersion,
                                result.latestVersion(), result.releaseUrl());
                        onResult.accept(result);
                    } else {
                        log.info("[UpdateChecker] Up to date (v{}).", currentVersion);
                    }
                });
            } catch (Exception e) {
                log.warn("[UpdateChecker] Could not check for updates: {}", e.getMessage());
            }
        });
    }

    private Optional<UpdateResult> fetchLatest() throws Exception {
        HttpURLConnection con = (HttpURLConnection) URI.create(API_URL).toURL().openConnection();
        con.setRequestMethod("GET");
        con.setRequestProperty("Accept", "application/vnd.github+json");
        con.setRequestProperty("User-Agent", "SecureAuth/" + currentVersion);
        con.setConnectTimeout(5_000);
        con.setReadTimeout(5_000);

        int code = con.getResponseCode();
        if (code == 404) {
            // No releases published yet
            log.debug("[UpdateChecker] No releases found on GitHub (404).");
            return Optional.empty();
        }
        if (code == 403) {
            log.warn("[UpdateChecker] GitHub rate-limit hit (403). Try again later.");
            return Optional.empty();
        }
        if (code != 200) {
            throw new Exception("GitHub API returned HTTP " + code);
        }

        String body;
        try (InputStream is = con.getInputStream()) {
            body = new String(is.readAllBytes());
        } finally {
            con.disconnect();
        }

        Matcher tagMatcher = TAG_PATTERN.matcher(body);
        if (!tagMatcher.find()) {
            log.warn("[UpdateChecker] Could not parse tag_name from GitHub response.");
            return Optional.empty();
        }
        String latestVersion = tagMatcher.group(1);

        Matcher urlMatcher = HTML_URL_PATTERN.matcher(body);
        String releaseUrl = urlMatcher.find() ? urlMatcher.group(1) : RELEASES_URL;

        return Optional.of(new UpdateResult(currentVersion, latestVersion, releaseUrl));
    }

    // ── Result ────────────────────────────────────────────────────────────────

    /**
     * Holds the outcome of a single update check.
     *
     * @param currentVersion running version (e.g. {@code "1.2.0"})
     * @param latestVersion  newest GitHub release tag (e.g. {@code "1.3.0"})
     * @param releaseUrl     URL to the release page
     */
    public record UpdateResult(String currentVersion, String latestVersion, String releaseUrl) {

        /**
         * {@code true} when {@link #latestVersion} is semantically newer than
         * {@link #currentVersion} using {@code MAJOR.MINOR.PATCH} comparison.
         * Pre-release suffixes (e.g. {@code -rc.1}) are treated as older than
         * the corresponding release.
         */
        public boolean isNewer() {
            return compare(latestVersion, currentVersion) > 0;
        }

        /**
         * Compares two version strings semantically.
         *
         * @return positive if {@code a > b}, 0 if equal, negative if {@code a < b}
         */
        public static int compare(String a, String b) {
            a = stripV(a);
            b = stripV(b);

            // Split off pre-release suffix: "1.2.0-rc.1" → ["1.2.0", "rc.1"]
            String[] aParts = a.split("-", 2);
            String[] bParts = b.split("-", 2);

            int[] aNums = toInts(aParts[0]);
            int[] bNums = toInts(bParts[0]);

            int len = Math.max(aNums.length, bNums.length);
            for (int i = 0; i < len; i++) {
                int av = i < aNums.length ? aNums[i] : 0;
                int bv = i < bNums.length ? bNums[i] : 0;
                if (av != bv)
                    return Integer.compare(av, bv);
            }
            // Same numeric: release > pre-release
            boolean aPre = aParts.length > 1;
            boolean bPre = bParts.length > 1;
            if (aPre && !bPre)
                return -1;
            if (!aPre && bPre)
                return 1;
            return 0;
        }

        private static String stripV(String v) {
            return (v != null && v.startsWith("v")) ? v.substring(1) : v;
        }

        private static int[] toInts(String dotted) {
            String[] parts = dotted.split("\\.");
            int[] nums = new int[parts.length];
            for (int i = 0; i < parts.length; i++) {
                try {
                    nums[i] = Integer.parseInt(parts[i]);
                } catch (NumberFormatException ignored) {
                    nums[i] = 0;
                }
            }
            return nums;
        }
    }
}
