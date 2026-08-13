package com.example.pqcauth.crypto;

import com.example.pqcauth.config.PqcProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Issues and verifies PQC-signed authentication tokens.
 *
 * <p>The token shape deliberately mirrors a JWS compact token
 * ({@code base64url(header).base64url(payload).base64url(signature)}) so it is
 * familiar to anyone who has worked with JWT, but the signature is produced by
 * a NIST post-quantum digital-signature algorithm (ML-DSA by default) instead
 * of RSA/ECDSA/HMAC.</p>
 *
 * <p><b>Security note:</b> the algorithm used to verify a token is always the
 * server's configured {@link PqcAlgorithm} and key -- the {@code alg} value
 * inside an incoming token's header is checked for equality but never used to
 * select the verification algorithm. This avoids classic "alg confusion" /
 * "alg:none" style attacks against header-driven verification.</p>
 */
@Service
public class PqcTokenService {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    private final PqcServerKeyPair serverKeyPair;
    private final PqcProperties properties;
    private final ObjectMapper objectMapper;

    public PqcTokenService(PqcServerKeyPair serverKeyPair, PqcProperties properties, ObjectMapper objectMapper) {
        this.serverKeyPair = serverKeyPair;
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    /**
     * Issues a new PQC-signed token for the given subject and roles.
     */
    public String issueToken(String subject, List<String> roles) {
        try {
            Instant now = Instant.now();
            Instant exp = now.plusSeconds(properties.getTokenTtlSeconds());

            Map<String, Object> header = new LinkedHashMap<>();
            header.put("alg", serverKeyPair.algorithm().name());
            header.put("typ", "PQC-AT");
            header.put("kid", serverKeyPair.keyId());

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("iss", properties.getIssuer());
            payload.put("sub", subject);
            payload.put("roles", roles);
            payload.put("iat", now.getEpochSecond());
            payload.put("exp", exp.getEpochSecond());
            payload.put("jti", UUID.randomUUID().toString());

            String headerB64 = B64.encodeToString(objectMapper.writeValueAsBytes(header));
            String payloadB64 = B64.encodeToString(objectMapper.writeValueAsBytes(payload));
            String signingInput = headerB64 + "." + payloadB64;

            byte[] signatureBytes = sign(signingInput.getBytes(StandardCharsets.UTF_8));
            String signatureB64 = B64.encodeToString(signatureBytes);

            return signingInput + "." + signatureB64;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to issue PQC token", e);
        }
    }

    /**
     * Verifies a PQC-signed token, returning its claims if the signature is
     * valid and the token has not expired.
     *
     * @throws PqcTokenValidationException if the token is malformed, the
     *                                      signature does not verify, or the
     *                                      token is expired.
     */
    public PqcTokenClaims verifyToken(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new PqcTokenValidationException("Malformed PQC token: expected 3 dot-separated segments");
        }
        String headerB64 = parts[0];
        String payloadB64 = parts[1];
        String signatureB64 = parts[2];

        Map<?, ?> header;
        Map<?, ?> payload;
        try {
            header = objectMapper.readValue(B64D.decode(headerB64), Map.class);
            payload = objectMapper.readValue(B64D.decode(payloadB64), Map.class);
        } catch (Exception e) {
            throw new PqcTokenValidationException("Malformed PQC token: cannot decode header/payload", e);
        }

        Object alg = header.get("alg");
        if (!Objects.equals(alg, serverKeyPair.algorithm().name())) {
            throw new PqcTokenValidationException(
                    "Unsupported or mismatched token algorithm: " + alg);
        }

        byte[] signatureBytes;
        try {
            signatureBytes = B64D.decode(signatureB64);
        } catch (IllegalArgumentException e) {
            throw new PqcTokenValidationException("Malformed PQC token: invalid signature encoding", e);
        }

        String signingInput = headerB64 + "." + payloadB64;
        boolean valid;
        try {
            valid = verify(signingInput.getBytes(StandardCharsets.UTF_8), signatureBytes);
        } catch (Exception e) {
            throw new PqcTokenValidationException("Signature verification error", e);
        }
        if (!valid) {
            throw new PqcTokenValidationException("PQC signature verification failed");
        }

        long exp = ((Number) payload.get("exp")).longValue();
        if (Instant.now().getEpochSecond() > exp) {
            throw new PqcTokenValidationException("PQC token expired");
        }

        String subject = String.valueOf(payload.get("sub"));
        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) payload.get("roles");
        long iat = ((Number) payload.get("iat")).longValue();
        String jti = String.valueOf(payload.get("jti"));

        return new PqcTokenClaims(subject, roles, iat, exp, jti);
    }

    private byte[] sign(byte[] data) throws Exception {
        java.security.Signature signature = java.security.Signature.getInstance(
                serverKeyPair.algorithm().jcaSignatureName(), BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(serverKeyPair.privateKey());
        signature.update(data);
        return signature.sign();
    }

    private boolean verify(byte[] data, byte[] signatureBytes) throws Exception {
        java.security.Signature signature = java.security.Signature.getInstance(
                serverKeyPair.algorithm().jcaSignatureName(), BouncyCastleProvider.PROVIDER_NAME);
        signature.initVerify(serverKeyPair.publicKey());
        signature.update(data);
        try {
            return signature.verify(signatureBytes);
        } catch (SignatureException e) {
            return false;
        }
    }
}
