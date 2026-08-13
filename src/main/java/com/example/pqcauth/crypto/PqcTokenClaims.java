package com.example.pqcauth.crypto;

import java.util.List;

/**
 * Verified claims extracted from a PQC authentication token.
 */
public record PqcTokenClaims(String subject, List<String> roles, long issuedAt, long expiresAt, String tokenId) {
}
