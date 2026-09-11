# Containerized CLI Login System with 2FA

[![Go Version](https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=flat&logo=go)](https://golang.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker)](https://www.docker.com/)
[![Database](https://img.shields.io/badge/PostgreSQL-16-336791?style=flat&logo=postgresql)](https://www.postgresql.org/)
[![Tests](https://img.shields.io/badge/Tests-Passing%20(100%25)-success)](./internal/service/)
[![Architecture](https://img.shields.io/badge/Architecture-Clean%20%2F%20Hexagonal-orange)](#architecture--design-decisions)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> Think of this as a **secure digital bank vault for your computer terminal**:
> - **Zero-Trust Login:** Users register and sign in with a password, but also get the option to turn on **Google Authenticator (2FA)**—generating 6-digit codes on their phone that change every 30 seconds.
> - **Anti-Hacking Shield:** If someone tries to guess a password 5 times, the system automatically freezes the account for 15 minutes to stop automated bots.
> - **Bank-Grade Data Privacy:** Passwords and login sessions are scrambled using one-way mathematical encryption. Even if someone steals the database, they cannot read any passwords or hijack accounts.
> - **Runs Everywhere (Docker):** Packed into lightweight virtual containers so anyone can launch the database and the app with a single command—no complex database configuration required.


---

## Architecture & Design Decisions

### Clean Architecture (Hexagonal / Ports & Adapters) Layout

The project adheres to strict dependency inversion rules. High-level business policies do not depend on low-level implementation details (such as SQL drivers or terminal line-readers); both depend on abstractions defined within the core domain.

```text
.
├── cmd/
│   └── cli/
│       └── main.go                 # Composition Root: Dependency Injection & wiring
│
├── internal/
│   ├── domain/                     # Core Business Entities & Port Contracts (Zero external imports)
│   │   ├── user.go                 # User & Session entities, sentinel domain errors
│   │   ├── repository.go           # Inbound/Outbound Storage Port interfaces
│   │   └── security.go             # Cryptographic Port interfaces (Hasher, TOTP, TokenGenerator)
│   │
│   ├── service/                    # Business Use-Case Layer (Pure business logic)
│   │   ├── auth_service.go         # Registration, Login, Lockout rules, Session validation
│   │   ├── mfa_service.go          # TOTP setup, verification, activation/disablement
│   │   ├── auth_service_test.go    # In-memory mock tests for auth, lockouts, and sessions
│   │   └── mfa_service_test.go     # In-memory mock tests for MFA lifecycle and challenge flows
│   │
│   ├── repository/postgres/        # Driven Adapter: Outbound DB Implementation (pgx/v5)
│   │   ├── db.go                   # Thread-safe pgxpool connection lifecycle management
│   │   ├── user_repo.go            # User persistence and atomic failed-attempt updates
│   │   └── session_repo.go         # Token hash storage, lookup, and deletion
│   │
│   ├── security/                   # Driven Adapter: Outbound Cryptographic Services
│   │   ├── hasher.go               # Bcrypt implementation of domain.PasswordHasher
│   │   └── totp.go                 # RFC 6238 TOTP engine & CSPRNG Token Generator
│   │
│   └── cli/                        # Driving Adapter: Inbound User Interface (chzyer/readline)
│       ├── repl.go                 # Interactive REPL loop, prompt dynamics, history
│       ├── completer.go            # State-aware dynamic tab-completion engine
│       └── commands.go             # Command routing, input sanitization, and output formatting
│
├── migrations/
│   └── 001_init.sql                # PostgreSQL DDL schema executed on container initialization
│
├── Dockerfile                      # Multi-stage static compilation build (Alpine runtime)
├── docker-compose.yml              # Service orchestration with persistent named volumes
└── go.mod
```

### Why Clean Architecture over MVC?
1. **Separation of Concerns:** MVC controllers in CLIs become bloated dumping grounds mixing terminal formatting with SQL queries. Clean Architecture keeps business rules (`service`) completely ignorant of terminal I/O (`cli`).
2. **Sub-Second In-Memory Testing:** Dependency inversion allows testing lockout counters, 2FA validation, and sessions without spinning up Docker or PostgreSQL.
3. **No Circular Imports:** Enforces inward-pointing dependencies (`domain <- service <- cli/repo`), eliminating Go's common package cycle issues.

---

## Threat Model & Security Controls

Authentication systems are prime targets for automated attacks, credential stuffing, and session hijacking. This project implements enterprise-grade defensive engineering across all architectural layers.

```text
Attacker Surface          Defense Layer                                      Implementation Mechanism
─────────────────────────────────────────────────────────────────────────────────────────────────────────────
Offline DB Dump       ──► One-Way Token Hashing & Salting             ──► SHA-256 (Sessions) & Bcrypt Cost 10 (Users)
Online Brute-Force    ──► Rate Limiting & Temporal Account Lockouts   ──► Exponential Backoff / Threshold Lockout
Session Hijacking     ──► High-Entropy CSPRNG Session Tokens          ──► 256-bit crypto/rand + Immediate Revocation
Credential Replay     ──► Time-Based One-Time Passwords (TOTP)        ──► RFC 6238 HMAC-SHA1 (30s Rolling Windows)
User Enumeration      ──► Constant-Time & Uniform Domain Errors       ──► Generic ErrInvalidCredentials
SQL Injection         ──► Native Binary Parameterization              ──► jackc/pgx/v5 Prepared Placeholders ($1..$n)
```

### 1. Credential Storage & Work Factor

* **Algorithm:** **Bcrypt** (`golang.org/x/crypto/bcrypt`).
* **Adaptive Work Factor (Cost = 10):** Hashing utilizes 1024 rounds of cryptographic key expansion ($2^{10}$). Each hash takes approximately 50–100ms to compute on modern CPU cores—negligible for an interactive terminal user, but computationally prohibitive for GPU-accelerated offline dictionary and rainbow-table attacks.
* **Automatic Per-User Salting:** Bcrypt generates a cryptographically secure 16-byte random salt embedded directly within the Modular Crypt Format string (`$2a$10$...`). Identical plaintext passwords produce completely distinct hashes, preventing bulk matching across users.
* **Zero Plaintext Footprint:** Raw passwords exist only as ephemeral byte slices in runtime memory and are never persisted, logged, or mapped to database models.

### 2. Brute-Force Mitigation & Account Lockout Algorithm

To prevent automated credential stuffing and dictionary attacks, the authentication engine enforces strict, persistent rate limiting:

**Threshold:** 5 failed attempts | **Lockout Duration:** 15 minutes

#### State Machine & Invariants:
1. **Consecutive Tracking:** Every failed password check OR failed 2FA verification atomically increments `failed_attempts` in PostgreSQL.
2. **Lockout Trigger:** When `failed_attempts >= 5`, the engine sets `locked_until = NOW() + 15 minutes`.
3. **Temporal Invalidation:** Any subsequent login attempt evaluates:
   `IF locked_until > NOW() -> ABORT with ErrAccountLocked`.
   *Even if the attacker enters the correct password while the account is locked, authentication is strictly rejected.*
4. **Successful Reset & Audit:** Upon entering the correct credentials (and valid TOTP when active), the engine executes an atomic reset:
   `failed_attempts = 0`, `locked_until = NULL`, `last_login_at = NOW()`.

### 3. Hardened Session Security & One-Way Token Hashing

Standard CLI applications often cut corners by storing raw session tokens or sequential integer IDs in the database. This system implements a **split-token defense model** (identical to the security architecture of GitHub and AWS):

```text
User Terminal Memory                                PostgreSQL Database (sessions table)
┌─────────────────────────┐                        ┌─────────────────────────────────────┐
│ Raw Token (Secret)      │                        │ Hashed Token (Lookup Key)           │
│ 32-byte CSPRNG hex      │ ─── SHA-256 Digest ──► │ 64-char Hex Digest                  │
│ [a7f3...6b89]           │                        │ [8f4e...91c2] (Raw token NEVER DB)  │
└─────────────────────────┘                        └─────────────────────────────────────┘
```

#### Why this eliminates Session Hijacking:
1. **256-Bit Cryptographic Entropy:** Tokens are generated using Go's `crypto/rand` (CSPRNG), reading directly from the host operating system's entropy pool (`/dev/urandom` on Linux). With 2^256 possible combinations, brute-forcing or predicting a token is mathematically impossible.
2. **Zero Plaintext Storage (At-Rest Protection):** The client holds the **raw token** in memory. The database **only stores the SHA-256 hash** of the token. 
   - *Impact:* Even in the event of a full SQL database leak or backup theft, an attacker cannot authenticate. Reversing a SHA-256 hash back into the raw token is computationally infeasible.
3. **Strict Temporal Expiration & Auto-Pruning:** Each session has a hard deadline (`expires_at = NOW() + 15m`). When validated via `ValidateSession`, if `NOW() > expires_at`, the record is immediately deleted from PostgreSQL and rejected with `ErrSessionExpired`.
4. **Instant Invalidation on Logout:** Explicit `logout` immediately executes `DELETE FROM sessions WHERE token_hash = $1`, preventing token replay attacks.

### 4. Two-Factor Authentication (RFC 6238 TOTP Engine)

* **Protocol:** Standard **Time-based One-Time Password** (TOTP) algorithm operating on 30-second rolling time windows with HMAC-SHA1 and 6-digit truncation (`pquerna/otp`).
* **Cryptographic Secret Generation:** Uses a 20-byte Base32 cryptographically random secret string.
* **Safe Activation Lifecycle (No Lockout Trap):** The system does not enable 2FA upon secret generation. It requires the user to successfully submit a valid 6-digit code from their authenticator app to prove setup before writing `mfa_enabled = true` to PostgreSQL.
* **Authenticator Compatibility:** Fully compliant with Google Authenticator, Authy, 1Password, and Bitwarden via standard `otpauth://totp/` URIs.

### 5. Architectural & Technology Selection Rationale

| Technology / Design Decision | Purpose in Stack | Rationale & Trade-Off Analysis |
| :--- | :--- | :--- |
| **Clean Architecture (Ports & Adapters)** | Architectural Decoupling | Completely isolates business rules from DB drivers and CLI formatting. Enables pure, sub-second unit tests using in-memory mock repositories with 0 running containers. |
| **`jackc/pgx/v5` with Connection Pooling** | Database Driver | Rejected ORMs (like GORM) to prevent hidden reflection overhead and query magic. `pgx` provides native binary protocol encoding, explicit transaction boundaries, thread-safe connection pooling (`pgxpool.Pool`), and parameter placeholder protection (`$1..$n`) preventing SQL injection. |
| **`chzyer/readline`** | Terminal Interactive REPL | Avoided standard `bufio.Scan` and bloated one-shot CLI frameworks like Cobra. `readline` provides native GNU Readline capabilities: persistent history across sessions, state-aware dynamic tab-completion (`<TAB>`), and silent password masking (`ReadPassword`). |
| **Multi-Stage Docker Build** | Container Security & Footprint | Stage 1 (`golang:1.26-alpine`) statically compiles the binary (`CGO_ENABLED=0 -ldflags="-s -w"`). Stage 2 (`alpine:3.19`) discards the Go compiler and build tools, producing a minimal attack surface image under 25MB. |
| **PostgreSQL Container with Named Volumes** | Persistence Infrastructure | Evaluated against SQLite. Running PostgreSQL in a dedicated container reflects real-world microservice architectures. Mapping a Docker named volume (`postgres_data:/var/lib/postgresql/data`) guarantees that user credentials and sessions persist across container stops, restarts, and redeployments. |

---

## Database Schema & Persistence Strategy

The application uses PostgreSQL 16. Data definitions are isolated in `migrations/001_init.sql` and executed automatically on first initialization via Docker's entrypoint mechanism.

```sql
-- 1. Users Entity Table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    totp_secret VARCHAR(64),
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. Sessions Entity Table
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for constant-time lookups
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
```

### Persistence Across Container Lifecycles
- **Volume Binding:** `postgres_data` is declared as a Docker named volume mounted directly to `/var/lib/postgresql/data`.
- **Durability Guarantee:** Stopping containers (`docker compose down`) or rebuilding the Go application does not touch volume storage. All registered users, password hashes, and MFA secrets survive reboots and updates.

---

## Prerequisites & Tech Stack

- **Docker & Docker Compose** (Docker Engine v24+)
- *(Optional for native host testing)* **Go 1.26+**

### Third-Party Dependencies
- `github.com/jackc/pgx/v5`: High-performance PostgreSQL driver and connection pooling.
- `github.com/chzyer/readline`: Pure Go GNU Readline line-editor with tab-completion and history.
- `golang.org/x/crypto/bcrypt`: Official Go cryptographic library for salted password hashing.
- `github.com/pquerna/otp`: RFC 6238 TOTP generation and validation engine.

---

## Installation & Quick Start (Dockerized)

### 1. Clone the Repository
```bash
git clone https://github.com/Mohammad-Niyas/Containerized-CLI-Login-System-with-2FA.git
cd Containerized-CLI-Login-System-with-2FA
```

### 2. Start the Stack & Launch the CLI
Run the persistent database container in the background:
```bash
docker compose up -d db
```

Launch the interactive CLI attached to your terminal session:
```bash
docker compose run --rm cli
```

---

## Local Development Workflow (Native Go)

For local development and debugging without running the Go binary inside a container:

1. **Ensure PostgreSQL is running in Docker:**
   ```bash
   docker compose up -d db
   ```
2. **Execute the application locally:**
   ```bash
   go run ./cmd/cli
   ```

---

## CLI Command Reference & User Guide

The CLI implements a stateful Read-Eval-Print Loop (REPL). Available commands change dynamically depending on whether a valid session is active.

```text
               ┌───────────────┐
               │ Program Start │
               └───────┬───────┘
                       │
                       ▼
          ┌─────────────────────────┐
          │ Unauthenticated State   │
          │ prompt: auth-cli>       │
          └────────────┬────────────┘
                       │
        ┌──────────────┴──────────────┐
        ▼                             ▼
   [register]                      [login]
(Create user)           (Password + TOTP check)
                                      │
                                      ▼
                        ┌───────────────────────────┐
                        │ Authenticated State       │
                        │ prompt: auth-cli (user)>  │
                        └─────────────┬─────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
    [whoami]                    [enable-2fa]                    [logout]
(View details)              (Setup Authenticator)            (End session)
```

### Command Matrix

| Command | Allowed State | Description |
| :--- | :--- | :--- |
| `register` | Pre-Login | Prompts for username and masked password (>= 8 chars). |
| `login` | Pre-Login | Authenticates username & password. Prompts for 6-digit TOTP if MFA is enabled. |
| `help` | Any | Context-aware listing of permitted commands. |
| `exit` | Any | Ends active session (if logged in) and terminates the program. |
| `whoami` | Post-Login | Displays username, registration date, MFA status, session TTL, and last login. |
| `enable-2fa` | Post-Login | Generates Base32 TOTP secret & URI; requires 6-digit confirmation to activate. |
| `disable-2fa` | Post-Login | Deactivates 2FA and revokes secret key on the account. |
| `logout` | Post-Login | Invalidates token in PostgreSQL, wipes in-memory session, and resets prompt. |

### Terminal Ergonomics
- **State-Aware Tab Completion:** Pressing `<TAB>` suggests only commands valid in the current authentication state.
- **Command History:** Use `<UP>` and `<DOWN>` arrow keys to navigate past inputs across sessions.
- **Password Masking:** Passwords are typed silently via `ReadPassword`, preventing shoulder-surfing.
- **Dynamic Prompt:** Prompt updates automatically from `auth-cli> ` to `auth-cli (<username>)> `.

---

## Configuration & Environment Variables

The application can be configured via environment variables in `docker-compose.yml` or runtime flags:

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `DB_HOST` | `localhost` (or `db` in Docker) | PostgreSQL host address |
| `DB_PORT` | `5432` | PostgreSQL network port |
| `DB_USER` | `auth_user` | Database user |
| `DB_PASSWORD` | `auth_password` | Database password |
| `DB_NAME` | `auth_db` | Database schema name |
| `MAX_FAILED_ATTEMPTS` | `5` | Failed attempts before triggering temporary lockout |
| `LOCKOUT_DURATION_MINUTES`| `15` | Temporary lockout duration in minutes |
| `SESSION_TIMEOUT_MINUTES` | `15` | Idle session validity window in minutes |

---

## Testing Strategy & Verification

Because the service layer depends entirely on domain interfaces, tests execute against fast in-memory mock repositories with zero external network or database overhead.

Execute the test suite:
```bash
go test -v ./internal/service/...
```

### Test Coverage Breakdown:
```text
=== RUN   TestAuthService_Register
--- PASS: TestAuthService_Register (0.00s)
=== RUN   TestAuthService_AccountLockout
--- PASS: TestAuthService_AccountLockout (0.01s)
=== RUN   TestAuthService_SessionValidation
--- PASS: TestAuthService_SessionValidation (0.15s)
=== RUN   TestMFAService_SetupAndEnable
--- PASS: TestMFAService_SetupAndEnable (0.00s)
=== RUN   TestAuthService_LoginWithMFAChallenge
--- PASS: TestAuthService_LoginWithMFAChallenge (0.01s)
PASS
ok      github.com/Mohammad-Niyas/Containerized-CLI-Login-System-with-2FA/internal/service  0.175s
```

- **`TestAuthService_Register`**: Verifies successful registration, rejection of usernames under duplicate constraints, and password length enforcement (>= 8).
- **`TestAuthService_AccountLockout`**: Verifies atomic incrementation of failed attempts, lockout trigger on the 5th attempt, and continued rejection during the active lockout window even with correct credentials.
- **`TestAuthService_SessionValidation`**: Verifies valid session resolution and automatic rejection after session TTL expiration.
- **`TestMFAService_SetupAndEnable`**: Tests secret generation, code rejection on invalid input, and proper activation upon receiving a valid RFC 6238 TOTP code.
- **`TestAuthService_LoginWithMFAChallenge`**: Tests 2-step challenge enforcement during login for MFA-enabled accounts.

---

## Edge Cases & Operational Resilience

1. **Database Reboots:** `pgxpool.Pool` manages automatic reconnection if the PostgreSQL container restarts.
2. **Session Cleanup:** Expired sessions are deleted on detection during validation, keeping the table lean.
3. **Manual Administrative Unlock (Emergency Debugging):**
   If an account is locked during testing and you do not wish to wait 15 minutes:
   ```bash
   docker exec -it auth_postgres psql -U auth_user -d auth_db -c "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = '<target_username>';"
   ```

---

## License

This project is licensed under the MIT License.
EOF
