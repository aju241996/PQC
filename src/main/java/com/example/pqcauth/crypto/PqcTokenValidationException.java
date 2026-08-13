package com.example.pqcauth.crypto;

/**
 * Thrown when a PQC authentication token fails validation (malformed, bad
 * signature, or expired).
 */
public class PqcTokenValidationException extends RuntimeException {

    public PqcTokenValidationException(String message) {
        super(message);
    }

    public PqcTokenValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
