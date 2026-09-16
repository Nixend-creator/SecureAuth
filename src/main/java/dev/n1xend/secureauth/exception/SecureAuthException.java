package dev.n1xend.secureauth.exception;

/** Base exception for all SecureAuth errors. */
public class SecureAuthException extends RuntimeException {
    public SecureAuthException(String message) {
        super(message);
    }

    public SecureAuthException(String message, Throwable cause) {
        super(message, cause);
    }
}
