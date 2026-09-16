package dev.n1xend.secureauth.command;

import dev.n1xend.secureauth.i18n.LanguageManager;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.jetbrains.annotations.NotNull;

/**
 * Base class for SecureAuth commands with common helpers.
 */
public abstract class CommandBase extends Command {

    protected final LanguageManager lang;

    protected CommandBase(String name, LanguageManager lang) {
        super(name);
        this.lang = lang;
    }

    @Override
    public abstract boolean execute(@NotNull CommandSender sender, @NotNull String commandLabel,
            @NotNull String[] args);

    protected boolean requirePlayer(CommandSender sender) {
        if (!(sender instanceof Player)) {
            lang.send(sender, "general.player-only");
            return false;
        }
        return true;
    }

    protected boolean requirePermission(CommandSender sender, String permission) {
        if (!sender.hasPermission(permission)) {
            lang.send(sender, "general.no-permission");
            return false;
        }
        return true;
    }
}
