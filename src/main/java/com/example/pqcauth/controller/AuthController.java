package com.example.pqcauth.controller;

import com.example.pqcauth.config.PqcProperties;
import com.example.pqcauth.crypto.PqcServerKeyPair;
import com.example.pqcauth.crypto.PqcTokenService;
import com.example.pqcauth.dto.LoginRequest;
import com.example.pqcauth.dto.RegisterRequest;
import com.example.pqcauth.dto.TokenResponse;
import com.example.pqcauth.model.AppUser;
import com.example.pqcauth.store.JpaUserStore;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Issues PQC-signed authentication tokens after verifying credentials, i.e.
 * the PQC analogue of a conventional "login -> JWT" endpoint.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final JpaUserStore userStore;
    private final PasswordEncoder passwordEncoder;
    private final PqcTokenService tokenService;
    private final PqcServerKeyPair serverKeyPair;
    private final PqcProperties properties;

    public AuthController(JpaUserStore userStore, PasswordEncoder passwordEncoder,
                           PqcTokenService tokenService, PqcServerKeyPair serverKeyPair,
                           PqcProperties properties) {
        this.userStore = userStore;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.serverKeyPair = serverKeyPair;
        this.properties = properties;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        boolean created = userStore.register(request.username(), passwordEncoder.encode(request.password()), List.of("USER"));
        if (!created) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists");
        }
        return ResponseEntity.status(HttpStatus.CREATED).body("User registered");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        AppUser user = userStore.findByUsername(request.username());
        if (user == null || !passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
        }

        String token = tokenService.issueToken(user.getUsername(), user.getRoles());
        TokenResponse response = new TokenResponse(
                "Bearer",
                serverKeyPair.algorithm().name(),
                token,
                properties.getTokenTtlSeconds(),
                user.getRoles());
        return ResponseEntity.ok(response);
    }
}
