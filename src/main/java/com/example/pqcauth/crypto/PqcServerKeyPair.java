package com.example.pqcauth.crypto;

import com.example.pqcauth.config.PqcProperties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Holds the server's signing key pair for the configured {@link PqcAlgorithm}.
 *
 * <p>The key pair is persisted in Postgres (see {@link PqcSigningKeyEntity}),
 * keyed by {@code kid}: on startup, an existing key for the configured
 * {@code kid} + algorithm is loaded rather than regenerated, so tokens
 * survive an application restart and every instance behind a load balancer
 * signs/verifies with the same key. A production deployment would likely
 * load the private key from a secrets manager / HSM instead of a database
 * column, but the {@code kid}-based rotation model here is the same either
 * way.</p>
 */
@Component
public class PqcServerKeyPair {

    private static final Logger log = LoggerFactory.getLogger(PqcServerKeyPair.class);

    static {
        // Defense-in-depth: guarantee the "BC" provider is registered before any PQC
        // key material is generated, regardless of bean-creation ordering.
        if (java.security.Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            java.security.Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final PqcAlgorithm algorithm;
    private final KeyPair keyPair;
    private final String keyId;

    public PqcServerKeyPair(PqcProperties properties, PqcSigningKeyRepository repository) {
        this.algorithm = properties.getAlgorithm();
        this.keyId = properties.getKeyId();
        this.keyPair = loadOrGenerate(algorithm, keyId, repository);
    }

    private static KeyPair loadOrGenerate(PqcAlgorithm algorithm, String keyId, PqcSigningKeyRepository repository) {
        return repository.findById(keyId)
                .filter(stored -> stored.getAlgorithm().equals(algorithm.name()))
                .map(stored -> decode(algorithm, stored))
                .orElseGet(() -> generateAndPersist(algorithm, keyId, repository));
    }

    private static KeyPair decode(PqcAlgorithm algorithm, PqcSigningKeyEntity stored) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(
                    algorithm.jcaKeyPairGeneratorName(), BouncyCastleProvider.PROVIDER_NAME);
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(stored.getPublicKey()));
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(stored.getPrivateKey()));
            log.info("Loaded persisted PQC signing key kid={} algorithm={}", stored.getKeyId(), algorithm);
            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to decode persisted PQC key pair for " + algorithm, e);
        }
    }

    private static KeyPair generateAndPersist(PqcAlgorithm algorithm, String keyId, PqcSigningKeyRepository repository) {
        KeyPair keyPair = generate(algorithm);
        repository.save(new PqcSigningKeyEntity(
                keyId, algorithm.name(), keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded()));
        log.info("Generated and persisted new PQC signing key kid={} algorithm={}", keyId, algorithm);
        return keyPair;
    }

    private static KeyPair generate(PqcAlgorithm algorithm) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(
                    algorithm.jcaKeyPairGeneratorName(), BouncyCastleProvider.PROVIDER_NAME);
            generator.initialize(algorithm.parameterSpec(), new SecureRandom());
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | java.security.InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Unable to generate PQC key pair for " + algorithm, e);
        }
    }

    public PqcAlgorithm algorithm() {
        return algorithm;
    }

    public String keyId() {
        return keyId;
    }

    public PrivateKey privateKey() {
        return keyPair.getPrivate();
    }

    public PublicKey publicKey() {
        return keyPair.getPublic();
    }

    public String publicKeyBase64() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }
}
