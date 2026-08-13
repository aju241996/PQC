package com.example.pqcauth.crypto;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Persisted form of the server's PQC signing key pair, keyed by {@code kid}
 * (see {@link com.example.pqcauth.config.PqcProperties#getKeyId()}).
 *
 * <p>Storing the key pair in Postgres (rather than regenerating it in memory
 * on every startup, as the original prototype did) is what makes tokens
 * survive an application restart and lets multiple instances behind a load
 * balancer sign/verify with the same key.</p>
 */
@Entity
@Table(name = "pqc_signing_keys")
public class PqcSigningKeyEntity {

    @Id
    @Column(length = 128)
    private String keyId;

    @Column(nullable = false, length = 64)
    private String algorithm;

    // Plain VARBINARY/BYTEA rather than @Lob("BLOB"): portable across H2 and
    // Postgres, and key material here is a few KB, not a streaming blob.
    // 8192 comfortably covers the largest supported key (ML-DSA-87).
    @Column(nullable = false, length = 8192)
    private byte[] publicKey;

    @Column(nullable = false, length = 8192)
    private byte[] privateKey;

    protected PqcSigningKeyEntity() {
        // JPA
    }

    public PqcSigningKeyEntity(String keyId, String algorithm, byte[] publicKey, byte[] privateKey) {
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String getKeyId() {
        return keyId;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }
}
