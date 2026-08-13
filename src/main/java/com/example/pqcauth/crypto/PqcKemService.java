package com.example.pqcauth.crypto;

import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * ML-KEM (CRYSTALS-Kyber) key encapsulation, offered alongside ML-DSA token
 * signing to mirror the paper's recommended "ML-KEM + ML-DSA" pairing for
 * Web/TLS-style deployments (Table 9). Clients can use this to establish a
 * shared secret with the server (e.g. to derive a symmetric key for
 * encrypting a request body) using the same lattice-based family recommended
 * as the fastest, lowest-energy KEM in the benchmark (Table 3, Table 7).
 */
@Service
public class PqcKemService {

    private static final MLKEMParameterSpec DEFAULT_LEVEL = MLKEMParameterSpec.ml_kem_768;

    /**
     * Generates a fresh ML-KEM key pair for a client-server exchange demo.
     */
    public KeyPair generateEphemeralKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            generator.initialize(DEFAULT_LEVEL, new SecureRandom());
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to generate ML-KEM key pair", e);
        }
    }

    /**
     * Server-side encapsulation against a client-supplied ML-KEM public key
     * (base64-encoded, X.509/SPKI format). Returns the ciphertext to send back
     * to the client and the resulting shared secret (base64), which a real
     * deployment would immediately feed into a KDF rather than exposing it
     * directly -- it is returned here only for demonstration purposes.
     */
    public KemResult encapsulate(String base64PublicKey) {
        try {
            byte[] pubKeyBytes = Base64.getDecoder().decode(base64PublicKey);
            KeyFactory keyFactory = KeyFactory.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubKeyBytes));

            KEM kem = KEM.getInstance("ML-KEM", BouncyCastleProvider.PROVIDER_NAME);
            KEM.Encapsulator encapsulator = kem.newEncapsulator(publicKey);
            KEM.Encapsulated encapsulated = encapsulator.encapsulate();

            SecretKey sharedSecret = encapsulated.key();
            return new KemResult(
                    Base64.getEncoder().encodeToString(encapsulated.encapsulation()),
                    Base64.getEncoder().encodeToString(sharedSecret.getEncoded()));
        } catch (Exception e) {
            throw new IllegalStateException("ML-KEM encapsulation failed", e);
        }
    }

    public record KemResult(String ciphertextBase64, String sharedSecretBase64) {
    }
}
