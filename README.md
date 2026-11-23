# `k-api` — Progressive Auth & Cryptography API + Defense-in-Depth Security Stack

`k-api` is a Go (`gin-gonic/gin`) API designed as an 11-level progressive authentication and cryptography challenge, paired with a production security operations stack covering **application hardening, zero-OS container runtime isolation, CrowdSec SIEM/IDS with Cloudflare Worker edge auto-containment, and containerized API Security Posture Management (ASPM)**.

- **Latest Automated Security Posture Report:** [`security/LATEST.md`](security/LATEST.md)

---

## Part 1: How the API Works

`k-api` exposes a sequential 11-rung authentication and cryptographic trust ladder. A client starts by initializing an ephemeral session at `GET /api` and must complete every level in order; each rung issues the cryptographic material or clearance permit required to unlock the next level.

### Architecture & Request Flow

```text
Client
  │
  ▼
Cloudflare Edge (TLS 1.2/1.3, Worker Bouncer + KV Ban List)
  │
  ▼
Cloudflare Tunnel (cloudflared → 127.0.0.1:8080, no public inbound ports)
  │
  ▼
k-api Container (Go 1.26 static binary, FROM scratch, read-only FS, UID 10001)
  │
  ├──► Structured stdout logs (log/slog) ──► CrowdSec Engine ──► Cloudflare Worker Bouncer
  └──► Inspected weekly by ASPM Container (DAST + gosec SAST + Trivy + Cloudflare Audit)
```

### The 11-Level Progressive Security Ladder

| Level | Endpoint | Mechanism / Challenge | Security Control Demonstrated |
| :--- | :--- | :--- | :--- |
| **Init** | `GET /api` | Ephemeral session bootstrap | Generates per-session ID and unique Basic Auth credentials |
| **1** | `GET /api/level/1` | HTTP Basic Authentication + `X-Session` | Constant-time credential verification (`crypto/subtle`) |
| **2** | `GET /api/level/2` | Custom identity header (`X-Identity-Token`) | Per-session token binding; issues signed HS256 JWT |
| **3** | `GET /api/level/3` | `Bearer` JWT authentication (`HS256`) | Middleware signature & expiration validation using HKDF-derived key |
| **4** | `GET /api/level/4` | Header MAC verification (`X-HMAC-Signature`) | Constant-time MAC verification; issues Level 5 clearance token |
| **5** | `POST /api/level/5` | Clearance verification + lattice warmup | Enforces sequential flow; encrypts Level 6 token with **AES-256-GCM** |
| **6** | `POST /api/level/6` | **AES-256-GCM** authenticated decryption | Proof of possession of decrypted plaintext; issues **Ed25519** challenge |
| **7** | `POST /api/level/7` | **Ed25519** asymmetric signature verification | Verifies signature over per-session challenge; issues **PBKDF2** parameters |
| **8** | `POST /api/level/8` | **PBKDF2-HMAC-SHA256** (120,000 iterations) | High-work-factor key derivation validation; issues **TOTP** salt & parameters |
| **9** | `POST /api/level/9` | **TOTP (RFC 6238, SHA-256, 8-digit)** | ±1 window tolerance + **single-use replay tracking** (`totpUsed`) |
| **10** | `GET /api/oauth/authorize`<br>`POST /api/oauth/token` | **OAuth 2.0 Authorization Code + PKCE (`S256`)** | Single-use 2-minute auth codes, `code_verifier` SHA-256 challenge validation, issues scoped JWT (`scope: level11`) |
| **11** | `POST /api/level/11`<br>`POST /api/level/11/solve` | Scoped JWT + **Learning With Errors (LWE)** lattice challenge | Post-quantum lattice problem $(\mathbf{A}, \mathbf{b} = \mathbf{A}\mathbf{s} + \mathbf{e} \bmod q)$ protecting an AES-256-GCM encrypted flag |

### Quick Start (Interacting with the API)

```bash
# 1. Health check
curl -i https://sample-api.com/health

# 2. Initialize a session (returns session ID + X-Next-Level-Auth header)
curl -i https://sample-api.com/api
```

---

## Part 2: Steps Taken to Secure the API

Security is enforced in four layers: **Application Controls**, **Container & Runtime Hardening**, **SIEM & Automated Edge Containment**, and **Continuous Posture Management (ASPM & SaaS/Cloud Posture)**.

### 1. Application-Layer Security (`*.go`)

- **Strict Sequential State Enforcement (`handlers.go`, `state.go`):** Every rung verifies that the caller holds valid state from the immediately preceding rung in addition to the current credential. Out-of-order requests or replayed OAuth/TOTP tokens are rejected.
- **Domain-Separated Key Derivation (`main.go`, `crypto.go`):** Secrets are never hardcoded. A high-entropy `INTERNAL_SEED` is expanded via HMAC-SHA256 counter-mode derivation (`deriveBytes`) with distinct domain labels (`jwt-level2-v1`, `jwt-level11-v1`, `aes-gcm-key-v1`, `totp-secret-v1`) so compromising one token type cannot forge another.
- **Side-Channel & Timing Mitigations (`crypto.go`):**
  - All secret, token, password, and MAC comparisons use `subtle.ConstantTimeCompare` (`ctEqual`).
  - Sensitive verification failures and successes apply randomized timing jitter (`jitterMs`) and deliberate failure backoff to frustrate timing side-channels and online brute forcing.
  - Cryptographic random integers use `crypto/rand.Int` (`randInt64n`) to avoid modulo bias and integer-conversion overflow (`gosec` `G115`).
- **Per-Client Token-Bucket Rate Limiting (`middleware.go`):**
  - Separate per-IP token buckets (`golang.org/x/time/rate`) enforce stricter limits on challenge and OAuth endpoints (`30 req/min`) than general routes (`120 req/min`).
  - Trusted proxy configuration (`SetTrustedProxies`) extracts the real client IP from Cloudflare's `X-Forwarded-For` header across the local Docker bridge rather than rate-limiting the NAT gateway.
- **Memory-Exhaustion Protection (`state.go`, `middleware.go`):** Background reaper goroutines evict idle rate-limit buckets, expired sessions (1-hour TTL), and expired OAuth authorization codes (2-minute TTL) so unauthenticated floods cannot grow memory unboundedly.
- **Defensive HTTP Response Headers (`middleware.go`):** Every response sets:
  - `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
  - `Strict-Transport-Security: max-age=63072000; includeSubDomains`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: no-referrer`

### 2. Container & Runtime Hardening (`Dockerfile`, `docker-compose.yml`, `helm/`)

- **Distroless `FROM scratch` Runtime Image (`Dockerfile`):**
  - Multi-stage build compiles a stripped static binary (`CGO_ENABLED=0`, `-ldflags="-s -w"`) and copies only the binary and CA certificates into `FROM scratch`.
  - **Zero OS packages and no shell (`/bin/sh` does not exist)** — eliminates OS-level CVE surface and prevents post-exploitation shell execution.
  - Runs as unprivileged UID/GID `10001:10001` with a built-in binary healthcheck (`["/app/k-api", "-healthcheck"]`).
- **Locked-Down Runtime (`docker-compose.yml`):**
  - `read_only: true` root filesystem.
  - Hard CPU (`cpus: '0.5'`) and memory (`mem_limit: 128m`) limits so a resource spike cannot starve the host (~2.6 MiB steady-state RAM usage).
  - Bound exclusively to host loopback (`127.0.0.1:8080:8080`); external traffic can only reach the service through the outbound-only Cloudflare Tunnel.
- **Hardened Kubernetes Reference Manifests (`helm/`):** Pod and container `securityContext` enforce `readOnlyRootFilesystem: true`, `runAsNonRoot: true`, `runAsUser/Group: 10001`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`, workload namespace isolation, and Istio `STRICT` mTLS / default-deny `NetworkPolicy`.

### 3. Dedicated SIEM, Detection & Automated Edge Containment

Designed to run within a tight host memory budget (~160 MiB total across all containers):

- **Direct Log Ingestion (`log/slog` → CrowdSec):** `k-api` emits structured `log/slog` events (`level passed`, `level failed`, `rate limited`) with client IP and failure reason to stdout. CrowdSec ingests the stream directly from the Docker socket without heavyweight log shippers.
- **Custom Parsers & Leaky-Bucket Scenarios:**
  - Custom CrowdSec grok parsers extract `source_ip`, `challenge_level`, `reason`, and event timestamps from `k-api` logs.
  - A custom leaky-bucket scenario (`crowdsecurity/k-api-bruteforce`, capacity 5, leak speed 30s) detects rapid authentication failures or rate-limit abuse per IP and triggers a 15-minute ban decision enriched with GeoIP/ASN metadata.
- **Automated Edge Blocking via Cloudflare Worker + KV Bouncer:**
  - `crowdsecurity/cloudflare-worker-bouncer` syncs local CrowdSec ban decisions into a Cloudflare Workers KV namespace and binds a remediation Worker in front of `*sample-api.com/*`.
  - Configured with **fail-open** request-limit handling (`request_limit_fail_open: true`) so worker quota or edge errors can never cause a denial of service against legitimate traffic.
- **Mobile Ban Summary Dashboard:** A lightweight (~40 MiB), HTTP Basic-Auth protected Python stdlib service polls the CrowdSec Local API (`/v1/decisions`) and renders a mobile-friendly summary of active bans, 24h/7d unique banned IPs, and recent triggers.

### 4. Continuous API Security Posture Management (ASPM) & Cloud Posture (`security/`)

A self-contained ASPM container (`golang:1.26-alpine` + `gosec` + `trivy` + `python3` + `crond`) runs weekly (Mondays 09:00 UTC) and on startup to audit code, container, infrastructure, and SaaS posture:

| Scan Stage | Tool / Script | What It Audits |
| :--- | :--- | :--- |
| **1. Live API DAST** | [`security/dast_probe.py`](security/dast_probe.py) | Probes the running API for exposed `.git`/`.env`/backup/SQL/config/debug/pprof/Swagger artifacts and verifies baseline HTTP security headers |
| **2. Go SAST** | `gosec` | Static analysis of all Go source files for cryptographic weaknesses, hardcoded secrets, SSRF, and unsafe integer conversions |
| **3. Container Vulnerability Scan** | `trivy image` | Scans the built `ghcr.io/bdwilliams3/api:latest` image for OS and Go module CVEs |
| **4. IaC & Config Posture** | `trivy config` | Audits `Dockerfile`, `docker-compose.yml`, and Kubernetes/Helm manifests against CIS/KSV benchmarks |
| **5. Cloudflare SaaS Posture** | [`security/cloudflare_audit.py`](security/cloudflare_audit.py) | Queries the Cloudflare v4 API to verify SSL mode (`full`/`strict`), minimum TLS version (`1.2+`), TLS 1.3 (`on`), security level, proxied DNS/tunnel records, and Worker route `fail-open` posture |
| **6. Report & Notification** | [`security/aggregate_report.py`](security/aggregate_report.py)<br>[`security/send_email.py`](security/send_email.py) | Writes [`security/LATEST.md`](security/LATEST.md) + dated weekly reports, commits/pushes to GitHub for automated or agent-assisted remediation, and emails the digest via SMTP |

### Current Posture Summary (from [`security/LATEST.md`](security/LATEST.md))

| Scanner | Critical | High | Medium | Low |
| :--- | :---: | :---: | :---: | :---: |
| **DAST (live API)** | 0 | 0 | 0 | 0 |
| **gosec (Go SAST)** | 0 | 0 | 0 | 0 |
| **Trivy (Container Image CVEs)** | 0 | 0 | 0 | 0 |
| **Trivy (Docker / IaC Config)** | 0 | 0 | 0 | 0 |

- **Cloudflare SaaS Posture:** `0` issues flagged (all checks passing — see [`security/LATEST.md`](security/LATEST.md))
