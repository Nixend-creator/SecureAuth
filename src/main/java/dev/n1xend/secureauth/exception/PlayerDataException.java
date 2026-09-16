package dev.n1xend.secureauth.exception;

public final class PlayerDataException extends SecureAuthException {
    public PlayerDataException(String message) {
        super(message);
    }

    public PlayerDataException(String message, Throwable cause) {
        super(message, cause);
    }
}
