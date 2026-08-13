package com.example.pqcauth.config;

import com.example.pqcauth.crypto.PqcAlgorithm;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Application-level configuration for PQC token authentication, exposed under
 * the {@code pqc.*} prefix in application.yml.
 */
@ConfigurationProperties(prefix = "pqc")
public class PqcProperties {

    /** Signature algorithm used to sign/verify authentication tokens. Defaults to the
     * paper's recommended general-purpose choice, ML-DSA-87 (NIST Level 5). */
    @NotNull
    private PqcAlgorithm algorithm = PqcAlgorithm.ML_DSA_87;

    /** Token lifetime in seconds. */
    @Positive
    private long tokenTtlSeconds = 900L;

    /** Issuer claim embedded in every issued token. */
    @NotNull
    private String issuer = "pqc-auth-demo";

    /** Key identifier advertised alongside the server's public key. */
    @NotNull
    private String keyId = "pqc-auth-key-1";

    public PqcAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(PqcAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public long getTokenTtlSeconds() {
        return tokenTtlSeconds;
    }

    public void setTokenTtlSeconds(long tokenTtlSeconds) {
        this.tokenTtlSeconds = tokenTtlSeconds;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }
}
