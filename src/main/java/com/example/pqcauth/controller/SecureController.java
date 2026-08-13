package com.example.pqcauth.controller;

import com.example.pqcauth.crypto.PqcTokenClaims;
import com.example.pqcauth.dto.UserProfileResponse;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Endpoints that require a valid PQC-signed bearer token, demonstrating that
 * {@link com.example.pqcauth.security.PqcTokenAuthenticationFilter} correctly
 * populates the Spring Security context from ML-DSA-verified claims.
 */
@RestController
@RequestMapping("/api/secure")
public class SecureController {

    @GetMapping("/profile")
    public UserProfileResponse profile(@AuthenticationPrincipal PqcTokenClaims principal) {
        return new UserProfileResponse(
                principal.subject(), principal.roles(), principal.issuedAt(), principal.expiresAt(), principal.tokenId());
    }

    @GetMapping("/admin/ping")
    public Map<String, String> adminPing() {
        return Map.of("status", "ok", "message", "You have ADMIN access via a PQC-signed token");
    }
}
