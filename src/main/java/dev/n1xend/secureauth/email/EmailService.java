package dev.n1xend.secureauth.email;

import dev.n1xend.secureauth.config.PluginConfig;
import jakarta.mail.*;
import jakarta.mail.internet.*;
import org.slf4j.Logger;

import java.security.SecureRandom;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;

/**
 * Sends password recovery emails via SMTP (Jakarta Mail).
 *
 * <p>All sending is done asynchronously on a Virtual Thread.
 */
public final class EmailService {

    private static final SecureRandom RNG = new SecureRandom();
    private static final char[] TOKEN_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789".toCharArray();

    private final PluginConfig config;
    private final Logger log;

    public EmailService(PluginConfig config, Logger log) {
        this.config = config;
        this.log = log;
    }

    /**
     * Generates a secure random recovery token.
     */
    public String generateToken() {
        StringBuilder sb = new StringBuilder(32);
        for (int i = 0; i < 32; i++) {
            sb.append(TOKEN_CHARS[RNG.nextInt(TOKEN_CHARS.length)]);
        }
        return sb.toString();
    }

    /**
     * Hashes a recovery token with SHA-256 for storage/comparison.
     *
     * <p>SHA-256 (not Argon2) is appropriate here: the token itself already
     * has ~186 bits of entropy from {@link #generateToken()} — it does not
     * need a slow, memory-hard hash to resist brute force the way a
     * human-chosen password does. This mirrors how session/reset tokens are
     * typically hashed in web applications.
     */
    public static String hashToken(String token) {
        try {
            java.security.MessageDigest sha256 = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash)
                hex.append(String.format("%02x", b));
            return hex.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e); // never happens on a real JVM
        }
    }

    /**
     * Sends a password recovery email asynchronously.
     *
     * @return CompletableFuture that completes with {@code true} on success
     */
    public CompletableFuture<Boolean> sendRecoveryEmail(String toEmail, String username, String token) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                doSend(toEmail, buildRecoverySubject(username), buildRecoveryBody(username, token));
                log.info("[Email] Recovery email sent to {} for player {}", toEmail, username);
                return true;
            } catch (Exception e) {
                log.error("[Email] Failed to send recovery email to {}: {}", toEmail, e.getMessage());
                return false;
            }
        }, Thread::startVirtualThread);
    }

    /**
     * Sends an email-ownership verification token for /setemail, asynchronously.
     *
     * @return CompletableFuture that completes with {@code true} on success
     */
    public CompletableFuture<Boolean> sendVerificationEmail(String toEmail, String username, String token) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                doSend(toEmail, buildVerificationSubject(username), buildVerificationBody(username, token));
                log.info("[Email] Verification email sent to {} for player {}", toEmail, username);
                return true;
            } catch (Exception e) {
                log.error("[Email] Failed to send verification email to {}: {}", toEmail, e.getMessage());
                return false;
            }
        }, Thread::startVirtualThread);
    }

    private void doSend(String to, String subject, String body)
            throws MessagingException, java.io.UnsupportedEncodingException {
        PluginConfig.EmailConfig cfg = config.getEmail();
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.host", cfg.smtpHost());
        props.put("mail.smtp.port", String.valueOf(cfg.smtpPort()));
        if (cfg.tls()) {
            // STARTTLS (port 587) — upgrade plain connection to TLS
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.starttls.required", "true");
        } else if (cfg.smtpPort() == 465) {
            // SSL/TLS (port 465) — SSL from the start
            props.put("mail.smtp.ssl.enable", "true");
        }
        props.put("mail.smtp.ssl.trust", cfg.smtpHost());
        props.put("mail.smtp.ssl.protocols", "TLSv1.2 TLSv1.3");
        // Connection and I/O timeout (ms) — prevents hanging forever
        props.put("mail.smtp.connectiontimeout", "10000");
        props.put("mail.smtp.timeout", "10000");
        props.put("mail.smtp.writetimeout", "10000");

        Session session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(cfg.username(), cfg.password());
            }
        });

        Message message = new MimeMessage(session);
        message.setFrom(new InternetAddress(cfg.from(), cfg.fromName()));
        message.setRecipient(Message.RecipientType.TO, new InternetAddress(to));
        message.setSubject(subject);
        message.setContent(body, "text/html; charset=utf-8");

        Transport.send(message);
    }

    private String buildRecoverySubject(String username) {
        return "Password Recovery for " + username;
    }

    private String buildRecoveryBody(String username, String token) {
        return """
                <html><body style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto">
                <h2 style="color: #2c3e50">🔐 Password Recovery</h2>
                <p>Hello, <strong>%s</strong>!</p>
                <p>Someone requested a password recovery for your Minecraft account.</p>
                <p><strong>Your recovery token:</strong></p>
                <div style="font-family: monospace; font-size: 1.4em; background: #f4f4f4;
                            border: 1px solid #ddd; padding: 12px; border-radius: 4px;
                            letter-spacing: 2px; text-align: center">%s</div>
                <p>Enter this token in-game to set a new password:<br>
                   <code style="background:#eee;padding:3px 6px">/recover confirm %s &lt;newpassword&gt;</code>
                </p>
                <p style="color: #e74c3c">⏱ This token expires in <strong>%d minutes</strong>.</p>
                <p style="color: #7f8c8d; font-size: 0.9em">
                   If you did not request this, you can safely ignore this email.
                </p>
                </body></html>
                """.formatted(username, token, token, config.getEmail().recoveryTokenTtlMinutes());
    }

    private String buildVerificationSubject(String username) {
        return "Confirm your recovery email for " + username;
    }

    private String buildVerificationBody(String username, String token) {
        return """
                <html><body style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto">
                <h2 style="color: #2c3e50">✉ Confirm Recovery Email</h2>
                <p>Hello, <strong>%s</strong>!</p>
                <p>You (or someone with your account's password) requested to link this
                   email address as your account's recovery email.</p>
                <p><strong>Your verification token:</strong></p>
                <div style="font-family: monospace; font-size: 1.4em; background: #f4f4f4;
                            border: 1px solid #ddd; padding: 12px; border-radius: 4px;
                            letter-spacing: 2px; text-align: center">%s</div>
                <p>Enter this token in-game to confirm:<br>
                   <code style="background:#eee;padding:3px 6px">/setemail confirm %s</code>
                </p>
                <p style="color: #e74c3c">⏱ This token expires in <strong>%d minutes</strong>.</p>
                <p style="color: #7f8c8d; font-size: 0.9em">
                   If you did not request this, you can safely ignore this email —
                   your account's recovery email will not change.
                </p>
                </body></html>
                """.formatted(username, token, token, config.getEmail().recoveryTokenTtlMinutes());
    }

    public boolean isEnabled() {
        return config.getEmail().enabled();
    }
}
