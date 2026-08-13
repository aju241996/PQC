package com.example.pqcauth.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;

/**
 * Lightweight, in-process microbenchmark of key generation, signing, and
 * verification for the configured PQC algorithm.
 *
 * <p>This mirrors -- at a much smaller scale and using {@code System.nanoTime}
 * rather than {@code perf_event_open} hardware cycle counters -- the
 * methodology described in Section 4.1 of the benchmarked paper: each
 * operation is run for {@code N} iterations and the average wall-clock cost
 * per operation is reported. It is meant to let an operator sanity-check, on
 * their own JVM/hardware, the relative ordering the paper found (ML-DSA
 * fastest, Falcon keygen expensive, SPHINCS+ signing expensive) rather than to
 * reproduce the paper's absolute cycle/energy figures, which require the
 * native liboqs harness, hardware perf counters, and AMD µProf power traces
 * used in the paper.</p>
 */
@Service
public class PqcBenchmarkService {

    public BenchmarkResult run(PqcAlgorithm algorithm, int iterations) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(
                    algorithm.jcaKeyPairGeneratorName(), BouncyCastleProvider.PROVIDER_NAME);
            SecureRandom random = new SecureRandom();
            byte[] message = "pqc-auth-benchmark-message".getBytes();

            long keyGenNanos = 0L;
            KeyPair lastKeyPair = null;
            int keygenIters = Math.max(1, Math.min(iterations, 50)); // keygen is the expensive op; cap it
            for (int i = 0; i < keygenIters; i++) {
                generator.initialize(algorithm.parameterSpec(), random);
                long start = System.nanoTime();
                lastKeyPair = generator.generateKeyPair();
                keyGenNanos += (System.nanoTime() - start);
            }

            Signature signer = Signature.getInstance(algorithm.jcaSignatureName(), BouncyCastleProvider.PROVIDER_NAME);
            long signNanos = 0L;
            byte[] lastSignature = null;
            for (int i = 0; i < iterations; i++) {
                signer.initSign(lastKeyPair.getPrivate());
                signer.update(message);
                long start = System.nanoTime();
                lastSignature = signer.sign();
                signNanos += (System.nanoTime() - start);
            }

            Signature verifier = Signature.getInstance(algorithm.jcaSignatureName(), BouncyCastleProvider.PROVIDER_NAME);
            long verifyNanos = 0L;
            for (int i = 0; i < iterations; i++) {
                verifier.initVerify(lastKeyPair.getPublic());
                verifier.update(message);
                long start = System.nanoTime();
                verifier.verify(lastSignature);
                verifyNanos += (System.nanoTime() - start);
            }

            return new BenchmarkResult(
                    algorithm.name(),
                    algorithm.family().name(),
                    algorithm.nistLevel(),
                    keygenIters,
                    iterations,
                    nanosToMillis(keyGenNanos, keygenIters),
                    nanosToMillis(signNanos, iterations),
                    nanosToMillis(verifyNanos, iterations),
                    lastKeyPair.getPublic().getEncoded().length,
                    lastSignature.length);
        } catch (Exception e) {
            throw new IllegalStateException("Benchmark failed for " + algorithm, e);
        }
    }

    private static double nanosToMillis(long totalNanos, int iterations) {
        return (totalNanos / (double) iterations) / 1_000_000.0;
    }

    public record BenchmarkResult(
            String algorithm,
            String family,
            String nistLevel,
            int keygenIterations,
            int signVerifyIterations,
            double avgKeyGenMillis,
            double avgSignMillis,
            double avgVerifyMillis,
            int publicKeyBytes,
            int signatureBytes) {
    }
}
