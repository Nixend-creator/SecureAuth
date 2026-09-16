package dev.n1xend.secureauth.util;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * IP address normalisation utilities.
 *
 * <p>Paper (and the underlying Java NIO stack) may represent the same client
 * address in different forms depending on whether the server socket is bound
 * to an IPv4 or a dual-stack IPv6 wildcard address:
 *
 * <ul>
 *   <li>Pure IPv4:        {@code 203.0.113.5}</li>
 *   <li>IPv4-mapped IPv6: {@code ::ffff:203.0.113.5} or
 *       {@code /0:0:0:0:0:ffff:cb00:7105}</li>
 *   <li>Loopback IPv4:    {@code 127.0.0.1}</li>
 *   <li>Loopback IPv6:    {@code ::1} or {@code 0:0:0:0:0:0:0:1}</li>
 * </ul>
 *
 * <p>Without normalisation the stored IP and the login IP can differ, causing
 * every session check to fail on dual-stack hosts even though both strings
 * represent the same network endpoint.
 */
public final class IpUtil {

    private IpUtil() {
    }

    /**
     * Normalises an IP address string to its canonical form:
     * <ul>
     *   <li>IPv4-mapped IPv6 addresses ({@code ::ffff:x.x.x.x}) are unwrapped
     *       to plain IPv4.</li>
     *   <li>IPv6 loopback ({@code ::1}) stays as {@code ::1}.</li>
     *   <li>All other addresses are returned in their
     *       {@link InetAddress#getHostAddress()} canonical form.</li>
     * </ul>
     *
     * @param raw the raw string from {@code InetAddress.getHostAddress()}
     * @return normalised address string; returns {@code raw} unchanged on any
     *         parse error so callers never receive {@code null}
     */
    public static String normalize(String raw) {
        if (raw == null || raw.isEmpty())
            return raw;
        try {
            InetAddress addr = InetAddress.getByName(raw);
            if (addr instanceof Inet6Address v6) {
                byte[] b = v6.getAddress();
                // IPv4-mapped: first 10 bytes 0x00, bytes 10-11 0xFF, last 4 bytes = IPv4
                if (isIpv4Mapped(b)) {
                    // Extract the embedded IPv4 address
                    InetAddress v4 = InetAddress.getByAddress(new byte[]{ b[12], b[13], b[14], b[15] });
                    return v4.getHostAddress();
                }
            }
            return addr.getHostAddress();
        } catch (UnknownHostException e) {
            // Unparseable — return as-is; comparisons may fail but won't crash
            return raw;
        }
    }

    /** Returns {@code true} if the 16-byte IPv6 address is an IPv4-mapped address. */
    private static boolean isIpv4Mapped(byte[] b) {
        if (b.length != 16)
            return false;
        for (int i = 0; i < 10; i++)
            if (b[i] != 0)
                return false;
        return b[10] == (byte) 0xFF && b[11] == (byte) 0xFF;
    }
}
