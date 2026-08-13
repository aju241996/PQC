package com.example.pqcauth.crypto;

import com.example.pqcauth.config.PqcProperties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Holds the server's signing key pair for the configured {@link PqcAlgorithm}.
 *
 * <p>The key pair is generated once at startup, in memory. This is intentionally
 * simple for demo purposes; a production deployment would load the private key
 * from a secrets manager / HSM and would support key rotation via {@code kid}.</p>
 */
@Component
public class PqcServerKeyPair {

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

    public PqcServerKeyPair(PqcProperties properties) {
        this.algorithm = properties.getAlgorithm();
        this.keyId = properties.getKeyId();
        this.keyPair = generate(algorithm);
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
