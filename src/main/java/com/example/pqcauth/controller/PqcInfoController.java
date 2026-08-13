package com.example.pqcauth.controller;

import com.example.pqcauth.crypto.PqcBenchmarkService;
import com.example.pqcauth.crypto.PqcKemService;
import com.example.pqcauth.crypto.PqcServerKeyPair;
import com.example.pqcauth.dto.KemDemoKeyPairResponse;
import com.example.pqcauth.dto.KemEncapsulateRequest;
import com.example.pqcauth.dto.PublicKeyResponse;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.KeyPair;
import java.util.Base64;

/**
 * Exposes the server's PQC public key and a couple of demo/diagnostic
 * endpoints (ML-KEM encapsulation, algorithm micro-benchmark) that tie this
 * service back to the benchmarking paper it implements.
 */
@RestController
@RequestMapping("/api/pqc")
public class PqcInfoController {

    private final PqcServerKeyPair serverKeyPair;
    private final PqcKemService kemService;
    private final PqcBenchmarkService benchmarkService;

    public PqcInfoController(PqcServerKeyPair serverKeyPair, PqcKemService kemService,
                              PqcBenchmarkService benchmarkService) {
        this.serverKeyPair = serverKeyPair;
        this.kemService = kemService;
        this.benchmarkService = benchmarkService;
    }

    /** Public: lets clients fetch the server's PQC signing public key (e.g. for offline verification). */
    @GetMapping("/public-key")
    public PublicKeyResponse publicKey() {
        return new PublicKeyResponse(
                serverKeyPair.keyId(),
                serverKeyPair.algorithm().name(),
                serverKeyPair.algorithm().family().name(),
                serverKeyPair.algorithm().nistLevel(),
                serverKeyPair.algorithm().description(),
                serverKeyPair.publicKeyBase64(),
                "X.509/SPKI");
    }

    /** Demo helper: generates a fresh ML-KEM key pair a test client can use with /kem/encapsulate. */
    @GetMapping("/kem/demo-keypair")
    public KemDemoKeyPairResponse kemDemoKeyPair() {
        KeyPair kp = kemService.generateEphemeralKeyPair();
        return new KemDemoKeyPairResponse(
                Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()),
                Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()),
                "ML-KEM-768");
    }

    /**
     * Server-side ML-KEM encapsulation against a client public key, mirroring the
     * paper's recommended ML-KEM + ML-DSA pairing for Web/TLS-style deployments
     * (Table 9). Requires authentication since it performs a per-request
     * cryptographic operation on behalf of the caller.
     */
    @PostMapping("/kem/encapsulate")
    public PqcKemService.KemResult encapsulate(@Valid @RequestBody KemEncapsulateRequest request) {
        return kemService.encapsulate(request.clientPublicKeyBase64());
    }

    /** Admin-only: runs a small in-process benchmark for the given algorithm, see {@link PqcBenchmarkService}. */
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/benchmark")
    public PqcBenchmarkService.BenchmarkResult benchmark(
            @RequestParam(defaultValue = "100") int iterations) {
        int bounded = Math.max(1, Math.min(iterations, 5000));
        return benchmarkService.run(serverKeyPair.algorithm(), bounded);
    }
}
