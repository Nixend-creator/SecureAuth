package dev.n1xend.secureauth.security;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.filter.AbstractFilter;
import org.apache.logging.log4j.message.Message;
import org.apache.logging.log4j.message.ParameterizedMessage;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Redacts plaintext credentials from server log output.
 *
 * <p><strong>Why this exists:</strong> Paper logs every command a player runs
 * with a line such as {@code "<player> issued server command: /login <pw>"}.
 * Since {@code /login}, {@code /register}, {@code /changepassword}, {@code /2fa}
 * and {@code /saadmin resetpassword} all carry secrets as plain command
 * arguments, the raw password / TOTP code ends up written to the console and
 * to {@code logs/latest.log} in plaintext — readable by anyone with log
 * access (hosting panel, FTP, a log-viewer plugin, a leaked backup, etc.)
 * without ever touching the database or cracking a hash.
 *
 * <p>A {@link org.apache.logging.log4j.core.Filter} cannot mutate a
 * {@link LogEvent}'s message — filters may only ACCEPT/DENY/pass a line
 * through unchanged. This filter therefore, on a match, immediately emits a
 * <em>replacement</em> line with the secret argument replaced by
 * {@code [REDACTED]} and then {@link Result#DENY}s the original event so the
 * real secret is never handed to any appender (console or file). The
 * replacement line is emitted with a marker that this same filter
 * recognises and passes straight through, avoiding infinite recursion.
 *
 * <p>Attached to the <em>root</em> {@link LoggerConfig} in
 * {@code SecureAuthPlugin#onLoad()} — as early in the server boot sequence as
 * a plugin can hook — because the log line in question is emitted by
 * Paper/Spigot's own command-dispatch code, not by this plugin's logger.
 */
public final class LogRedactionFilter extends AbstractFilter {

    private static final Marker ALREADY_REDACTED = org.apache.logging.log4j.MarkerManager
            .getMarker("SECUREAUTH_REDACTED");

    /**
     * Matches the standard Bukkit/Paper "issued server command" log line for
     * each auth command that carries a secret as an argument, capturing the
     * command portion (group 1) so it can be preserved in the redacted output.
     * Covers common aliases ({@code /l}, {@code /reg}) as well as the
     * canonical command names. Case-insensitive since Bukkit matches command
     * names case-insensitively.
     */
    private static final List<Pattern> COMMAND_PATTERNS = List.of(
            Pattern.compile("(?i)(.*issued server command:\\s*/(?:login|l))\\s+\\S.*"),
            Pattern.compile("(?i)(.*issued server command:\\s*/(?:register|reg))\\s+\\S.*"),
            Pattern.compile("(?i)(.*issued server command:\\s*/changepassword)\\s+\\S.*"),
            Pattern.compile("(?i)(.*issued server command:\\s*/2fa\\s+\\S+)\\s+\\S.*"),
            Pattern.compile("(?i)(.*issued server command:\\s*/recover)\\s+\\S.*"),
            Pattern.compile("(?i)(.*issued server command:\\s*/saadmin\\s+resetpassword\\s+\\S+)\\s+\\S.*"));

    @Override
    public Result filter(LogEvent event) {
        if (event.getMarker() == ALREADY_REDACTED)
            return Result.NEUTRAL;
        return process(event.getLoggerName(), event.getLevel(), event.getMessage().getFormattedMessage());
    }

    @Override
    public Result filter(Logger logger, Level level, Marker marker, Message msg, Throwable t) {
        if (marker == ALREADY_REDACTED)
            return Result.NEUTRAL;
        return process(logger.getName(), level, msg.getFormattedMessage());
    }

    @Override
    public Result filter(Logger logger, Level level, Marker marker, Object msg, Throwable t) {
        if (marker == ALREADY_REDACTED)
            return Result.NEUTRAL;
        return process(logger.getName(), level, String.valueOf(msg));
    }

    @Override
    public Result filter(Logger logger, Level level, Marker marker, String msg, Object... params) {
        if (marker == ALREADY_REDACTED)
            return Result.NEUTRAL;
        String formatted = (params == null || params.length == 0) ? msg : ParameterizedMessage.format(msg, params);
        return process(logger.getName(), level, formatted);
    }

    private Result process(String loggerName, Level level, String message) {
        if (message == null)
            return Result.NEUTRAL;
        for (Pattern p : COMMAND_PATTERNS) {
            Matcher m = p.matcher(message);
            if (m.matches()) {
                LogManager.getLogger(loggerName).log(level, ALREADY_REDACTED, m.group(1) + " [REDACTED]");
                return Result.DENY;
            }
        }
        return Result.NEUTRAL;
    }

    /** Attaches this filter to the root logger config so it sees every log event. */
    public static LogRedactionFilter install() {
        LogRedactionFilter filter = new LogRedactionFilter();
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration config = ctx.getConfiguration();
        LoggerConfig rootConfig = config.getRootLogger();
        rootConfig.addFilter(filter);
        ctx.updateLoggers();
        return filter;
    }

    /** Detaches this filter instance from the root logger config. */
    public void uninstall() {
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration config = ctx.getConfiguration();
        config.getRootLogger().removeFilter(this);
        ctx.updateLoggers();
    }
}
