package com.example.pqcauth.crypto;

/**
 * Mathematical family a PQC algorithm belongs to, mirroring the taxonomy used in
 * "The Energy Cost of Post-Quantum Transition: Benchmarking PQC Algorithms on
 * Commodity Hardware" (Jindal, Judd &amp; Uludag, HPDC '26), Section 2.2 / Figure 1.
 */
public enum PqcFamily {
    LATTICE_BASED,
    CODE_BASED,
    HASH_BASED
}
