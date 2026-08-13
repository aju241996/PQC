package com.example.pqcauth.dto;

import java.util.List;

public record UserProfileResponse(
        String username,
        List<String> roles,
        long tokenIssuedAt,
        long tokenExpiresAt,
        String tokenId) {
}
