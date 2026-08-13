package com.example.pqcauth.config;

import com.example.pqcauth.crypto.PqcTokenService;
import com.example.pqcauth.security.PqcTokenAuthenticationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.time.Instant;
import java.util.Map;

/**
 * Wires the PQC token filter into Spring Security as a stateless bearer-token
 * scheme: no HTTP sessions, no CSRF (there is no cookie-based auth to protect
 * against), public auth/info endpoints, everything else requires a valid
 * ML-DSA-signed token.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public PqcTokenAuthenticationFilter pqcTokenAuthenticationFilter(PqcTokenService tokenService) {
        return new PqcTokenAuthenticationFilter(tokenService);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                     PqcTokenAuthenticationFilter pqcTokenAuthenticationFilter,
                                                     ObjectMapper objectMapper) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**", "/api/pqc/public-key", "/actuator/health").permitAll()
                        .requestMatchers("/api/secure/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .exceptionHandling(eh -> eh
                        .authenticationEntryPoint((request, response, ex) ->
                                writeError(response, objectMapper, 401, "Unauthorized",
                                        "Missing or invalid PQC bearer token", request.getRequestURI()))
                        .accessDeniedHandler((request, response, ex) ->
                                writeError(response, objectMapper, 403, "Forbidden",
                                        "Insufficient role for this resource", request.getRequestURI())))
                .addFilterBefore(pqcTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    private static void writeError(jakarta.servlet.http.HttpServletResponse response, ObjectMapper objectMapper,
                                    int status, String error, String message, String path) throws java.io.IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        Map<String, Object> body = Map.of(
                "timestamp", Instant.now().toString(),
                "status", status,
                "error", error,
                "message", message,
                "path", path);
        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}
