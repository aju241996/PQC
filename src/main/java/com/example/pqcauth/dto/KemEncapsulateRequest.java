package com.example.pqcauth.dto;

import jakarta.validation.constraints.NotBlank;

/** Client-supplied ML-KEM public key (X.509/SPKI, base64) to encapsulate against. */
public record KemEncapsulateRequest(@NotBlank String clientPublicKeyBase64) {
}
