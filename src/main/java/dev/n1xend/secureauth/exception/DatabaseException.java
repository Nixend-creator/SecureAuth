package dev.n1xend.secureauth.exception;

public final class DatabaseException extends SecureAuthException {
    public DatabaseException(String message) {
        super(message);
    }

    public DatabaseException(String message, Throwable cause) {
        super(message, cause);
    }
}
