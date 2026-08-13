package com.example.pqcauth.crypto;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Digital-signature algorithms this service can use to sign PQC authentication
 * tokens, wired up to the exact JCA/Bouncy Castle names verified against
 * {@code bcprov-jdk18on:1.79}.
 *
 * <p>The catalogue and the recommended defaults are taken directly from the
 * benchmarking paper this project implements: lattice-based ML-DSA is the
 * paper's recommended default signature scheme for "Web / TLS" style
 * deployments (Table 9, Section 6.2) because it offers sub-millijoule,
 * sub-millisecond signing/verification at NIST Level 5 (Table 8, Figure 4),
 * while Falcon and SPHINCS+ are offered as alternatives for the
 * "bandwidth-limited / fast verification" and "trust anchor" scenarios the
 * paper also describes.</p>
 */
public enum PqcAlgorithm {

    ML_DSA_44("ML-DSA", "ML-DSA", MLDSAParameterSpec.ml_dsa_44, PqcFamily.LATTICE_BASED, "L2",
            "CRYSTALS-Dilithium / ML-DSA, NIST Level 2 (lowest available ML-DSA parameter set)."),
    ML_DSA_65("ML-DSA", "ML-DSA", MLDSAParameterSpec.ml_dsa_65, PqcFamily.LATTICE_BASED, "L3",
            "CRYSTALS-Dilithium / ML-DSA, NIST Level 3."),
    ML_DSA_87("ML-DSA", "ML-DSA", MLDSAParameterSpec.ml_dsa_87, PqcFamily.LATTICE_BASED, "L5",
            "CRYSTALS-Dilithium / ML-DSA, NIST Level 5. Paper's recommended default DSA " +
                    "for general-purpose / Web-TLS deployments (lowest energy & latency, Table 9)."),

    FALCON_512("FALCON", "FALCON", FalconParameterSpec.falcon_512, PqcFamily.LATTICE_BASED, "L1",
            "Falcon-512, NIST Level 1. Compact signatures, fast verification, expensive keygen."),
    FALCON_1024("FALCON", "FALCON", FalconParameterSpec.falcon_1024, PqcFamily.LATTICE_BASED, "L5",
            "Falcon-1024, NIST Level 5. Favored for bandwidth-limited / fast-verification " +
                    "scenarios (Table 9) at the cost of expensive key generation (Table 4)."),

    SPHINCS_PLUS_SHA2_128F("SPHINCSPLUS", "SPHINCSPLUS", SPHINCSPlusParameterSpec.sha2_128f,
            PqcFamily.HASH_BASED, "L1",
            "SPHINCS+-SHA2-128f, NIST Level 1. Conservative, stateless hash-based security " +
                    "at the cost of very large signatures and slow signing (Table 4/6)."),
    SPHINCS_PLUS_SHA2_256F("SPHINCSPLUS", "SPHINCSPLUS", SPHINCSPlusParameterSpec.sha2_256f,
            PqcFamily.HASH_BASED, "L5",
            "SPHINCS+-SHA2-256f, NIST Level 5. Recommended by the paper for 'trust anchor' " +
                    "deployments that require hash-based assurance (Table 9).");

    private final String jcaKeyPairGeneratorName;
    private final String jcaSignatureName;
    private final AlgorithmParameterSpec parameterSpec;
    private final PqcFamily family;
    private final String nistLevel;
    private final String description;

    PqcAlgorithm(String jcaKeyPairGeneratorName, String jcaSignatureName, AlgorithmParameterSpec parameterSpec,
                 PqcFamily family, String nistLevel, String description) {
        this.jcaKeyPairGeneratorName = jcaKeyPairGeneratorName;
        this.jcaSignatureName = jcaSignatureName;
        this.parameterSpec = parameterSpec;
        this.family = family;
        this.nistLevel = nistLevel;
        this.description = description;
    }

    public String jcaKeyPairGeneratorName() {
        return jcaKeyPairGeneratorName;
    }

    public String jcaSignatureName() {
        return jcaSignatureName;
    }

    public AlgorithmParameterSpec parameterSpec() {
        return parameterSpec;
    }

    public PqcFamily family() {
        return family;
    }

    public String nistLevel() {
        return nistLevel;
    }

    public String description() {
        return description;
    }
}
