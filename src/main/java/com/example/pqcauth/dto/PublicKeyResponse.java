package com.example.pqcauth.dto;

public record PublicKeyResponse(
        String keyId,
        String algorithm,
        String family,
        String nistLevel,
        String description,
        String publicKeyBase64,
        String publicKeyFormat) {
}
