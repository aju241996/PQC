package com.example.pqcauth.security;

import com.example.pqcauth.crypto.PqcTokenClaims;
import com.example.pqcauth.crypto.PqcTokenService;
import com.example.pqcauth.crypto.PqcTokenValidationException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Reads the {@code Authorization: Bearer <pqc-token>} header, verifies the
 * token's post-quantum signature via {@link PqcTokenService}, and, if valid,
 * populates the Spring Security context so downstream {@code @PreAuthorize}
 * / authorization rules work exactly as they would with a conventional JWT
 * filter.
 *
 * <p>Invalid or missing tokens are simply left unauthenticated here; the
 * decision to reject the request is deferred to Spring Security's standard
 * {@code authorizeHttpRequests} rules (see {@code SecurityConfig}), which keeps
 * this filter's responsibility narrow and testable.</p>
 */
public class PqcTokenAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final PqcTokenService tokenService;

    public PqcTokenAuthenticationFilter(PqcTokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                     @NonNull HttpServletResponse response,
                                     @NonNull FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length()).trim();
            try {
                PqcTokenClaims claims = tokenService.verifyToken(token);
                List<GrantedAuthority> authorities = claims.roles().stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .map(GrantedAuthority.class::cast)
                        .toList();

                var authentication = new UsernamePasswordAuthenticationToken(claims, token, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (PqcTokenValidationException ex) {
                SecurityContextHolder.clearContext();
                // Leave unauthenticated; entry point / access-denied handling takes over downstream.
            }
        }
        filterChain.doFilter(request, response);
    }
}
