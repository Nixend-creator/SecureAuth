package dev.n1xend.secureauth.geoip;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CountryResponse;
import dev.n1xend.secureauth.config.PluginConfig;
import org.slf4j.Logger;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.List;
import java.util.Optional;

/**
 * GeoIP country lookup using MaxMind GeoLite2-Country database.
 *
 * <p>The database file must be downloaded separately from MaxMind
 * and placed at the path specified in config ({@code geoip.database-path}).
 */
public final class GeoIpService {

    private final PluginConfig config;
    private final Logger log;
    private DatabaseReader reader;

    public GeoIpService(PluginConfig config, Logger log) {
        this.config = config;
        this.log = log;
        initialize();
    }

    private void initialize() {
        PluginConfig.GeoIpConfig cfg = config.getGeoIp();
        if (!cfg.enabled())
            return;

        File dbFile = new File(cfg.databasePath());
        if (!dbFile.exists()) {
            log.warn("[GeoIP] Database file not found at '{}'. GeoIP features disabled.", cfg.databasePath());
            log.warn(
                    "[GeoIP] Download GeoLite2-Country.mmdb from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data");
            return;
        }

        try {
            reader = new DatabaseReader.Builder(dbFile).build();
            log.info("[GeoIP] Database loaded: {}", dbFile.getName());
        } catch (IOException e) {
            log.error("[GeoIP] Failed to load database: {}", e.getMessage());
        }
    }

    /**
     * Looks up the ISO 3166-1 alpha-2 country code for an IP address.
     *
     * @return ISO country code (e.g. "RU"), or empty if lookup fails
     */
    public Optional<String> getCountryCode(String ip) {
        if (reader == null)
            return Optional.empty();
        try {
            InetAddress addr = InetAddress.getByName(ip);
            CountryResponse response = reader.country(addr);
            return Optional.ofNullable(response.getCountry().getIsoCode());
        } catch (IOException | GeoIp2Exception e) {
            return Optional.empty();
        }
    }

    /**
     * Returns whether the given IP is allowed to connect based on GeoIP config.
     *
     * @return {@code true} if allowed, {@code false} if blocked
     */
    public boolean isAllowed(String ip) {
        PluginConfig.GeoIpConfig cfg = config.getGeoIp();
        if (!cfg.enabled() || reader == null)
            return true;

        Optional<String> countryOpt = getCountryCode(ip);
        if (countryOpt.isEmpty())
            return true; // Unknown — allow by default

        String country = countryOpt.get().toUpperCase();

        // If blocked-countries list is set, block those
        List<String> blocked = cfg.blockedCountries();
        if (!blocked.isEmpty() && blocked.stream().anyMatch(c -> c.equalsIgnoreCase(country))) {
            return false;
        }

        // If allowed-countries list is set (whitelist mode), only allow those
        List<String> allowed = cfg.allowedCountries();
        if (!allowed.isEmpty()) {
            return allowed.stream().anyMatch(c -> c.equalsIgnoreCase(country));
        }

        return true;
    }

    public boolean isEnabled() {
        return config.getGeoIp().enabled() && reader != null;
    }

    public void close() {
        if (reader != null) {
            try {
                reader.close();
            } catch (IOException ignored) {
            }
        }
    }
}
