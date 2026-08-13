package com.example.pqcauth.crypto;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.security.KeyPair;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class PqcKemFlowTest {

    @Autowired
    private PqcKemService kemService;

    @Test
    void encapsulateAgainstFreshKeyPairSucceeds() {
        KeyPair kp = kemService.generateEphemeralKeyPair();
        String pub = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());

        PqcKemService.KemResult result = kemService.encapsulate(pub);

        assertThat(result.ciphertextBase64()).isNotBlank();
        assertThat(result.sharedSecretBase64()).isNotBlank();
    }
}
