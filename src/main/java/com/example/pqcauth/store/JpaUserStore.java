package com.example.pqcauth.store;

import com.example.pqcauth.model.AppUser;
import jakarta.annotation.PostConstruct;
import org.springframework.dao.DataAccessException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Postgres-backed user store, seeded with the same demo accounts the
 * in-memory prototype used, so the authentication flow can be exercised
 * end-to-end without any manual setup. Swap the seeding for a real
 * onboarding flow in production.
 */
@Component
public class JpaUserStore {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public JpaUserStore(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    void seedDemoUsers() {
        register("alice", passwordEncoder.encode("changeit"), List.of("USER"));
        register("admin", passwordEncoder.encode("changeit"), List.of("USER", "ADMIN"));
    }

    public AppUser findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

    /**
     * Registers a new user with an already-hashed password. Returns
     * {@code false} if the username is already taken.
     */
    public boolean register(String username, String passwordHash, List<String> roles) {
        if (userRepository.findByUsername(username).isPresent()) {
            return false;
        }
        try {
            userRepository.save(new AppUser(username, passwordHash, roles));
            return true;
        } catch (DataAccessException raceLostToUniqueConstraint) {
            return false;
        }
    }
}
