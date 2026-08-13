package com.example.pqcauth.dto;

import java.util.List;

public record TokenResponse(
        String tokenType,
        String algorithm,
        String accessToken,
        long expiresInSeconds,
        List<String> roles) {
}
