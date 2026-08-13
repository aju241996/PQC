package com.example.pqcauth.crypto;

import com.example.pqcauth.config.PqcProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the behavior {@link PqcServerKeyPair} exists for: a signing key
 * persisted by one instance is reloaded (not regenerated) by the next, which
 * is what lets tokens survive a restart and lets multiple app instances
 * share one signing identity.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class PqcServerKeyPairPersistenceTest {

    @Autowired
    private PqcSigningKeyRepository repository;

    @Test
    void secondInstanceReusesThePersistedKeyInsteadOfGeneratingANewOne() {
        PqcProperties properties = new PqcProperties();
        properties.setAlgorithm(PqcAlgorithm.ML_DSA_44); // smallest key, fastest test

        PqcServerKeyPair first = new PqcServerKeyPair(properties, repository);
        PqcServerKeyPair second = new PqcServerKeyPair(properties, repository);

        assertThat(repository.findById(properties.getKeyId())).isPresent();
        assertThat(second.publicKeyBase64()).isEqualTo(first.publicKeyBase64());
    }
}
