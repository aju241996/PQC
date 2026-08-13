package com.example.pqcauth;

import com.example.pqcauth.config.PqcProperties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import java.security.Security;

/**
 * Spring Boot application demonstrating post-quantum-cryptography (PQC) based
 * token authentication.
 *
 * <p>Design decisions are informed by "The Energy Cost of Post-Quantum
 * Transition: Benchmarking PQC Algorithms on Commodity Hardware"
 * (Jindal, Judd &amp; Uludag, HPDC '26): the paper benchmarks NIST-standardized
 * KEMs (ML-KEM, HQC, BIKE, Classic McEliece) and signature schemes (ML-DSA,
 * Falcon, SPHINCS+) for CPU cycles, artifact size, memory, and energy, and
 * recommends ML-KEM + ML-DSA as the default pairing for "Web / TLS" style
 * deployments because it is consistently the fastest and most energy-efficient
 * combination (Section 6.2, Table 9). This service signs bearer tokens with
 * ML-DSA by default (see {@link PqcProperties}) and exposes an ML-KEM
 * key-encapsulation endpoint for establishing a shared secret, mirroring that
 * recommended pairing.</p>
 */
@SpringBootApplication
@EnableConfigurationProperties(PqcProperties.class)
public class PqcAuthApplication {

    static {
        // Register Bouncy Castle as soon as this class is loaded (not only when main()
        // runs), so ML-DSA / ML-KEM / Falcon / SPHINCS+ JCA algorithm names resolve via
        // the "BC" provider both in the running application and in @SpringBootTest
        // contexts, which bootstrap this class without ever calling main().
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(PqcAuthApplication.class, args);
    }
}
