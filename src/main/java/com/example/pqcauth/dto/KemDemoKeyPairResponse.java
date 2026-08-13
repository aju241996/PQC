package com.example.pqcauth.dto;

/** Convenience endpoint response bundling a freshly generated ML-KEM key pair for demos/tests. */
public record KemDemoKeyPairResponse(String publicKeyBase64, String privateKeyBase64, String algorithm) {
}
