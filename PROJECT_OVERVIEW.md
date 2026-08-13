# PQC — Post-Quantum-Cryptography Auth (pqc-auth-spring-boot)

A Spring Boot REST API implementing JWT-like bearer-token authentication signed
with **ML-DSA** (post-quantum digital signatures, formerly CRYSTALS-Dilithium)
instead of RSA/HMAC/ECDSA, plus an **ML-KEM** (post-quantum key encapsulation,
formerly CRYSTALS-Kyber) demo endpoint. BouncyCastle (`bcprov-jdk18on`)
supplies the actual PQC algorithm implementations, since the JDK does not
ship them natively.

Design decisions follow *"The Energy Cost of Post-Quantum Transition:
Benchmarking PQC Algorithms on Commodity Hardware"* (Jindal, Judd & Uludag,
HPDC '26), which recommends **ML-KEM + ML-DSA** as the fastest,
lowest-energy pairing for Web/TLS-style deployments.

- Location on disk: `/Users/ajaybachhal/git/PQC`
- Eclipse workspace project name: `PQC`
- Maven coordinates: `com.example:pqc-auth-spring-boot:1.0.0`
- Stack: Java 21, Spring Boot 3.3.4 (web, security, validation, actuator, data-jpa), BouncyCastle 1.79, Postgres (H2 for tests)

## Suggested reading order

1. **`crypto/PqcAlgorithm.java`** — start here. Enum catalog of supported
   algorithms (ML-DSA-44/65/87, Falcon-512/1024, SPHINCS+-SHA2-128f/256f)
   with their JCA names, NIST security levels, and tradeoffs. Everything
   else operates on this "menu".
2. **`config/PqcProperties.java` + `resources/application.yml`** — the
   `pqc.*` settings: active algorithm (default `ML_DSA_87`), token TTL,
   issuer, key ID.
3. **`crypto/PqcServerKeyPair.java`** — loads the server's signing key pair
   from Postgres if one is already stored for the configured `kid`;
   otherwise generates one and persists it (see `PqcSigningKeyEntity`).
   This means tokens survive an app restart and every instance behind a
   load balancer signs/verifies with the same key. A production deployment
   would likely load the private key from a secrets manager/HSM instead of
   a database column, but the `kid`-based rotation model is the same.
4. **`crypto/PqcTokenService.java`** — the core. `issueToken()` builds a
   JWT-shaped token (`base64url(header).base64url(payload).base64url(signature)`)
   but signs it with ML-DSA; `verifyToken()` checks the signature and
   expiry. Security note: the verification algorithm is always the
   server's configured one, never read from the token's own `alg` header
   — this blocks "alg confusion" / "alg:none" style attacks.
5. **`security/PqcTokenAuthenticationFilter.java`** — servlet filter that
   reads `Authorization: Bearer <token>`, calls `verifyToken()`, and
   populates Spring Security's context with claims/roles if valid. Invalid
   tokens are left unauthenticated; rejection is deferred to Spring
   Security's standard rules.
6. **`config/SecurityConfig.java`** — wires the filter into Spring
   Security: stateless (no sessions), CSRF disabled (no cookie-based auth
   to protect), `/api/auth/**` and `/api/pqc/public-key` public,
   `/api/secure/admin/**` requires `ROLE_ADMIN`, everything else requires
   any valid token.
7. **Controllers** (the HTTP surface):
   - `AuthController` — `POST /api/auth/register`, `POST /api/auth/login`
     (checks BCrypt password hash, then calls `tokenService.issueToken()`).
   - `SecureController` — `GET /api/secure/profile` (any authenticated
     user), `GET /api/secure/admin/ping` (ADMIN only) — proves the
     filter → security-context → `@PreAuthorize`/role chain works.
   - `PqcInfoController` — `GET /api/pqc/public-key` (fetch server's PQC
     public key), `GET /api/pqc/kem/demo-keypair` + `POST
     /api/pqc/kem/encapsulate` (ML-KEM exchange demo), `GET
     /api/pqc/benchmark` (ADMIN-only micro-benchmark of keygen/sign/verify
     timing).
8. **`store/JpaUserStore.java`** — Postgres-backed via `UserRepository`
   (Spring Data JPA over the `AppUser` entity). Seeds `alice`/`changeit`
   (role `USER`) and `admin`/`changeit` (roles `USER`, `ADMIN`) on startup
   if they don't already exist in the database.
9. **Tests** — `PqcTokenFlowTests.java` and `PqcKemFlowTest.java` exercise
   the login → token → secure-endpoint flow and the KEM flow end-to-end;
   `PqcServerKeyPairPersistenceTest.java` proves a second `PqcServerKeyPair`
   reloads the persisted key instead of generating a new one. Tests run
   against H2 in PostgreSQL-compatibility mode (`src/test/resources/application.yml`)
   so they don't require a live Postgres instance.

## Package layout

```
src/main/java/com/example/pqcauth/
├── PqcAuthApplication.java        entry point; registers BouncyCastle ("BC") provider
├── config/
│   ├── PqcProperties.java         pqc.* settings (algorithm, ttl, issuer, keyId)
│   └── SecurityConfig.java        Spring Security filter chain wiring
├── controller/
│   ├── AuthController.java        /api/auth/register, /api/auth/login
│   ├── SecureController.java      /api/secure/profile, /api/secure/admin/ping
│   └── PqcInfoController.java     /api/pqc/public-key, /kem/*, /benchmark
├── crypto/
│   ├── PqcAlgorithm.java          enum of supported signature algorithms
│   ├── PqcFamily.java             LATTICE_BASED / HASH_BASED classification
│   ├── PqcServerKeyPair.java      loads/generates + persists the signing key pair
│   ├── PqcSigningKeyEntity.java   JPA entity: persisted key pair (kid, algorithm, bytes)
│   ├── PqcSigningKeyRepository.java
│   ├── PqcTokenService.java       issueToken() / verifyToken()
│   ├── PqcTokenClaims.java        verified claims record (sub, roles, iat, exp, jti)
│   ├── PqcTokenValidationException.java
│   ├── PqcKemService.java         ML-KEM key generation + encapsulation
│   └── PqcBenchmarkService.java   in-process keygen/sign/verify timing
├── security/
│   └── PqcTokenAuthenticationFilter.java   Bearer-token filter
├── store/
│   ├── JpaUserStore.java          Postgres-backed user store; seeds demo users
│   └── UserRepository.java        Spring Data JPA repository over AppUser
├── model/
│   └── AppUser.java                JPA entity: app_users + app_user_roles tables
├── dto/                            request/response records (LoginRequest,
│                                    RegisterRequest, TokenResponse,
│                                    PublicKeyResponse, KemDemoKeyPairResponse,
│                                    KemEncapsulateRequest, UserProfileResponse,
│                                    ErrorResponse)
└── exception/
    └── GlobalExceptionHandler.java
```

## Runtime flow

```
POST /api/auth/login {username,password}
   → JpaUserStore lookup (Postgres) + BCrypt check
   → PqcTokenService.issueToken()  (signs header+payload with ML-DSA private key)
   → returns TokenResponse{tokenType, algorithm, token, ttlSeconds, roles}

GET /api/secure/profile   (Authorization: Bearer <token>)
   → PqcTokenAuthenticationFilter verifies signature via server's ML-DSA public key
     (alg in header is checked for equality only, never used to select the verifier)
   → populates SecurityContext with PqcTokenClaims + ROLE_* authorities
   → SecurityConfig's authorizeHttpRequests / @PreAuthorize enforce access
```

## Token shape

Mirrors a JWS compact token so it's familiar to anyone who's used JWT, but
the signature algorithm is a NIST PQC scheme instead of RSA/ECDSA/HMAC:

```
base64url(header) . base64url(payload) . base64url(signature)

header:  { "alg": "ML_DSA_87", "typ": "PQC-AT", "kid": "pqc-auth-key-1" }
payload: { "iss": "pqc-auth-demo", "sub": "alice", "roles": ["USER"],
           "iat": ..., "exp": ..., "jti": "<uuid>" }
signature: ML-DSA signature over "base64url(header).base64url(payload)"
```

## Algorithm catalog (`PqcAlgorithm`)

| Enum | Family | NIST Level | Notes |
|---|---|---|---|
| `ML_DSA_44` | Lattice | L2 | Lowest available ML-DSA parameter set |
| `ML_DSA_65` | Lattice | L3 | |
| `ML_DSA_87` | Lattice | L5 | **Default.** Paper's recommended DSA for general-purpose/Web-TLS (lowest energy & latency) |
| `FALCON_512` | Lattice | L1 | Compact signatures, fast verify, expensive keygen |
| `FALCON_1024` | Lattice | L5 | Bandwidth-limited/fast-verification scenarios |
| `SPHINCS_PLUS_SHA2_128F` | Hash | L1 | Conservative, stateless hash-based; large/slow signatures |
| `SPHINCS_PLUS_SHA2_256F` | Hash | L5 | Recommended for "trust anchor" deployments |

Default KEM for the `/api/pqc/kem/*` endpoints is **ML-KEM-768**.

## Endpoints reference

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/auth/register` | public | create a user (default role `USER`) |
| POST | `/api/auth/login` | public | verify credentials, issue PQC token |
| GET | `/api/pqc/public-key` | public | fetch server's ML-DSA public key |
| GET | `/api/pqc/kem/demo-keypair` | token | generate a demo ML-KEM key pair |
| POST | `/api/pqc/kem/encapsulate` | token | server-side ML-KEM encapsulation against client pubkey |
| GET | `/api/pqc/benchmark` | ADMIN | keygen/sign/verify micro-benchmark |
| GET | `/api/secure/profile` | token | echoes the authenticated principal's claims |
| GET | `/api/secure/admin/ping` | ADMIN | proves role-based authorization works |
| GET | `/actuator/health` | public | Spring Boot health check |

## Demo credentials (seeded into Postgres on first startup)

| Username | Password | Roles |
|---|---|---|
| `alice` | `changeit` | USER |
| `admin` | `changeit` | USER, ADMIN |

`JpaUserStore.seedDemoUsers()` (a `@PostConstruct`) inserts these only if
they don't already exist, so re-deploying doesn't reset or duplicate them.

## Persistence (Postgres)

Both the user store and the server's signing key pair are now backed by
Postgres, which is what makes the service restart-safe and horizontally
scalable — a prerequisite for a real AWS deployment (ECS/EKS + RDS):

- **Tables** (auto-created via `spring.jpa.hibernate.ddl-auto: update` —
  fine for this demo; switch to Flyway/Liquibase + `ddl-auto: validate`
  for a managed deployment):
  - `app_users` / `app_user_roles` — users and their roles.
  - `pqc_signing_keys` — one row per `kid`, storing `algorithm` and the
    X.509/PKCS8-encoded public/private key bytes (`VARBINARY(8192)`, sized
    for the largest supported key, ML-DSA-87). **Not** `@Lob`/`BLOB`: H2's
    PostgreSQL-compatibility mode (used for tests) doesn't understand the
    `BLOB` keyword, and Hibernate logs that as a non-fatal warning rather
    than failing startup — the missing table only surfaces later as
    `Table "PQC_SIGNING_KEYS" not found`. Plain `VARBINARY`/`BYTEA` sidesteps
    it and is portable across both databases.
- **Local/dev config** (`src/main/resources/application.yml`): connects to
  `jdbc:postgresql://localhost:5432/pqcauth`, overridable via
  `SPRING_DATASOURCE_URL` / `_USERNAME` / `_PASSWORD` env vars — the same
  vars an ECS task definition or `docker run -e` would set for RDS.
- **Test config** (`src/test/resources/application.yml`): points at H2 in
  PostgreSQL-compatibility mode instead, so `mvn test` runs without a live
  Postgres/Docker. Maven puts `target/test-classes` ahead of
  `target/classes` on the test classpath, so this file wins for `mvn test`
  while the real Postgres config still applies to `mvn spring-boot:run`.
  A future improvement would be Testcontainers for closer-to-prod test
  fidelity.
- **Key rotation model**: `PqcServerKeyPair` looks up `pqc_signing_keys` by
  the configured `kid` (`pqc.key-id`) + algorithm. To rotate, change
  `pqc.key-id` to a new value — a fresh key is generated and persisted
  under the new id, and old tokens signed under the previous `kid` remain
  verifiable only if that old row is still queried (current code always
  verifies against the *currently configured* `kid`, so a rotation is a
  hard cutover, not a grace-period overlap — a real rollout would need to
  keep both keys queryable during transition).

## Known demo-only simplifications

- `ddl-auto: update` auto-migrates the schema; a managed deployment should
  use Flyway/Liquibase with `ddl-auto: validate` instead.
- Key rotation is a hard cutover (see above), not a grace-period overlap.
- ML-KEM shared secret is returned directly in the API response for
  demonstration; a real deployment would feed it into a KDF instead of
  exposing it.
- No AWS deployment artifacts yet (Dockerfile, ECS task definition/Terraform,
  RDS provisioning) — this covers the persistence layer only.
