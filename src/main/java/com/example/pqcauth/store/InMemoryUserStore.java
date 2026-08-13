package com.example.pqcauth.store;

import com.example.pqcauth.model.AppUser;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A simple in-memory user store, seeded with a demo account, so the
 * authentication flow can be exercised end-to-end without a database.
 * Swap this out for a real repository in production.
 */
@Component
public class InMemoryUserStore {

    private final Map<String, AppUser> users = new ConcurrentHashMap<>();

    public InMemoryUserStore(PasswordEncoder passwordEncoder) {
        users.put("alice", new AppUser("alice", passwordEncoder.encode("changeit"), List.of("USER")));
        users.put("admin", new AppUser("admin", passwordEncoder.encode("changeit"), List.of("USER", "ADMIN")));
    }

    public AppUser findByUsername(String username) {
        return users.get(username);
    }

    public boolean register(String username, String passwordHash, List<String> roles) {
        return users.putIfAbsent(username, new AppUser(username, passwordHash, roles)) == null;
    }
}
