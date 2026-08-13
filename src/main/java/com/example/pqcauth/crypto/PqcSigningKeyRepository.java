package com.example.pqcauth.crypto;

import org.springframework.data.jpa.repository.JpaRepository;

public interface PqcSigningKeyRepository extends JpaRepository<PqcSigningKeyEntity, String> {
}
