package com.example.pqcauth.model;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.ArrayList;
import java.util.List;

/**
 * A user record for the demo authentication flow, persisted in Postgres.
 *
 * <p>Roles are fetched eagerly: the list is always small and always needed
 * (token issuance, {@code /api/secure/profile}), so eager fetch avoids
 * {@code LazyInitializationException} once the entity crosses the repository
 * call's transaction boundary, without resorting to open-session-in-view.</p>
 */
@Entity
@Table(name = "app_users")
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String username;

    @Column(nullable = false)
    private String passwordHash;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "app_user_roles", joinColumns = @jakarta.persistence.JoinColumn(name = "user_id"))
    @Column(name = "role")
    private List<String> roles = new ArrayList<>();

    protected AppUser() {
        // JPA
    }

    public AppUser(String username, String passwordHash, List<String> roles) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.roles = new ArrayList<>(roles);
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public List<String> getRoles() {
        return roles;
    }
}
