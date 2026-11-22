# Weekly Security Posture Report — 2026-11-22

- Target: `https://sample-api.com`
- Generated: 2026-11-22 04:19 UTC

## Summary

| Source | Critical | High | Medium | Low |
|---|---|---|---|---|
| DAST (live API) | 0 | 0 | 0 | 5 |
| gosec (Go SAST) | 0 | 4 | 0 | 0 |
| Trivy (image CVEs) | 0 | 9 | 18 | 4 |
| Trivy (Docker/IaC config) | 9 | 13 | 28 | 104 |

Cloudflare posture: 2 issue(s) flagged.

## Live API scan — DAST

- **[LOW]** Missing security header: Content-Security-Policy — /health response is missing the Content-Security-Policy header
- **[LOW]** Missing security header: Referrer-Policy — /health response is missing the Referrer-Policy header
- **[LOW]** Missing security header: Strict-Transport-Security — /health response is missing the Strict-Transport-Security header
- **[LOW]** Missing security header: X-Content-Type-Options — /health response is missing the X-Content-Type-Options header
- **[LOW]** Missing security header: X-Frame-Options — /health response is missing the X-Frame-Options header

## Source code — gosec (SAST)

- **[HIGH]** G101 — /repo/handlers.go:372-376 — Potential hardcoded credentials (code: 371: 		"next": "/api/oauth/authorize", 372: 		"oauth": gin.H{ 373: 			"client_id": oauthClient, 374: 			"authorize": "/api/oauth/authorize", 375: 			"token":     "/api/oaut…
- **[HIGH]** G115 — /repo/crypto.go:124 — integer overflow conversion uint64 -> int64 (code: 123: 	} 124: 	return int64(v % uint64(q)) 125: })
- **[HIGH]** G115 — /repo/crypto.go:124 — integer overflow conversion int64 -> uint64 (code: 123: 	} 124: 	return int64(v % uint64(q)) 125: })
- **[HIGH]** G115 — /repo/crypto.go:66 — integer overflow conversion int64 -> byte (code: 65: 	for i := 0; i < 8; i++ { 66: 		msg[7-i] = byte(counter >> (8 * i)) 67: 	})

## Container image — Trivy (CVEs)

- **[HIGH]** CVE-2026-25681 · golang.org/x/net v0.54.0 → 0.55.0 — root/k-api — golang.org/x/net/html: golang.org/x/net/html: Arbitrary code execution via Cross-Site Scripting
- **[HIGH]** CVE-2026-27136 · golang.org/x/net v0.54.0 → 0.55.0 — root/k-api — golang.org/x/net/html: golang: golang.org/x/net/html: Cross-Site Scripting via HTML parsing bypass
- **[HIGH]** CVE-2026-39821 · golang.org/x/net v0.54.0 → 0.55.0 — root/k-api — golang.org/x/net/idna: golang: net/http: golang.org/x/net/idna: Privilege escalation via incorrect Punycode label processing
- **[HIGH]** CVE-2026-46600 · golang.org/x/net v0.54.0 → 0.56.0 — root/k-api — golang.org/x/net/dns/dnsmessage: golang.org/x/net/dns/dnsmessage: Denial of Service via invalid DNS record parsing
- **[HIGH]** CVE-2026-56851 · golang.org/x/text v0.37.0 → 0.41.0 — root/k-api — golang.org/x/text: golang.org/x/text: Denial of Service via out-of-bounds slice error in Nickname profile
- **[HIGH]** CVE-2026-56852 · golang.org/x/text v0.37.0 → 0.39.0 — root/k-api — golang.org/x/text: golang.org/x/text: Denial of Service via invalid UTF-8 input
- **[HIGH]** CVE-2026-56854 · golang.org/x/crypto v0.52.0 → 0.55.0 — root/k-api — golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Authentication bypass due to unenforced source-address restrictions
- **[HIGH]** CVE-2026-78661 · golang.org/x/net v0.54.0 → 0.62.0 — root/k-api — golang.org/x/net/html: golang.org/x/net/html: Denial of Service via crafted HTML input
- **[HIGH]** CVE-2026-78669 · golang.org/x/net v0.54.0 → 0.60.0 — root/k-api — net/http: net/http/internal/http2: golang.org/x/net/http2: net/http: Denial of Service via excessive HTTP/2 SETTINGS frames
- **[MEDIUM]** CVE-2026-107496 · libcrypto3 3.5.9-r0 → 3.5.9-r1 — ghcr.io/bdwilliams3/api:latest (alpine 3.24.4) — openssl: openssl: Denial of Service via crafted EC certificate in CMS encryption
- **[MEDIUM]** CVE-2026-107496 · libssl3 3.5.9-r0 → 3.5.9-r1 — ghcr.io/bdwilliams3/api:latest (alpine 3.24.4) — openssl: openssl: Denial of Service via crafted EC certificate in CMS encryption
- **[MEDIUM]** CVE-2026-25680 · golang.org/x/net v0.54.0 → 0.55.0 — root/k-api — golang.org/x/net/html: golang.org/x/net/html: Denial of Service due to excessive HTML parsing
- **[MEDIUM]** CVE-2026-40898 · github.com/quic-go/quic-go v0.59.0 → 0.59.1 — root/k-api — github.com/quic-go/quic-go: quic-go: Denial of Service via excessive memory allocation in HTTP/3 trailers
- **[MEDIUM]** CVE-2026-42502 · golang.org/x/net v0.54.0 → 0.55.0 — root/k-api — golang.org/x/net/html: golang: golang.org/x/net/html: Cross-Site Scripting via unexpected HTML tree rendering
- **[MEDIUM]** CVE-2026-42506 · golang.org/x/net v0.54.0 → 0.55.0 — root/k-api — golang.org/x/net/html: golang.org/x/net/html: Cross-Site Scripting (XSS) via arbitrary HTML parsing
- **[MEDIUM]** CVE-2026-4738 · zlib 1.3.2-r1 → 1.4-r0 — ghcr.io/bdwilliams3/api:latest (alpine 3.24.4) — Improper Restriction of Operations within the Bounds of a Memory Buffe ...
- **[MEDIUM]** CVE-2026-56855 · golang.org/x/crypto v0.52.0 → 0.56.0 — root/k-api — golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of Service via crafted messages
- **[MEDIUM]** CVE-2026-78659 · golang.org/x/net v0.54.0 → 0.60.0 — root/k-api — net/http: golang.org/x/net/http2: golang: net/http: Denial of Service via HTTP/2 trailer header memory exhaustion
- **[MEDIUM]** CVE-2026-78660 · golang.org/x/net v0.54.0 → 0.60.0 — root/k-api — net/http: golang: golang.org/x/net/http2: net/http: HTTP response smuggling via malformed HTTP/2 framing headers
- **[MEDIUM]** CVE-2026-78662 · golang.org/x/crypto v0.52.0 → 0.56.0 — root/k-api — golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of Service via channel request flooding
  …and 12 more (see artifacts).

## Docker / compose / Helm — Trivy (misconfig)

- **[CRITICAL]** KSV-0041 · Manage secrets — helm/flux-system/gotk-components.yaml:140 — ClusterRole 'crd-controller-flux-system' shouldn't have access to manage resource 'secrets'
- **[CRITICAL]** KSV-0046 · Manage all resources — helm/flux-system/gotk-components.yaml:134 — ClusterRole 'crd-controller-flux-system' shouldn't manage all resources
- **[CRITICAL]** KSV-0046 · Manage all resources — helm/flux-system/gotk-components.yaml:110 — ClusterRole 'crd-controller-flux-system' shouldn't manage all resources
- **[CRITICAL]** KSV-0046 · Manage all resources — helm/flux-system/gotk-components.yaml:104 — ClusterRole 'crd-controller-flux-system' shouldn't manage all resources
- **[CRITICAL]** KSV-0046 · Manage all resources — helm/flux-system/gotk-components.yaml:116 — ClusterRole 'crd-controller-flux-system' shouldn't manage all resources
- **[CRITICAL]** KSV-0046 · Manage all resources — helm/flux-system/gotk-components.yaml:122 — ClusterRole 'crd-controller-flux-system' shouldn't manage all resources
- **[CRITICAL]** KSV-0046 · Manage all resources — helm/flux-system/gotk-components.yaml:128 — ClusterRole 'crd-controller-flux-system' shouldn't manage all resources
- **[CRITICAL]** KSV-0046 · Manage all resources — helm/flux-system/gotk-components.yaml:212 — ClusterRole 'flux-edit-flux-system' shouldn't manage all resources
- **[CRITICAL]** KSV-0046 · Manage all resources — helm/flux-system/gotk-components.yaml:240 — ClusterRole 'flux-view-flux-system' shouldn't manage all resources
- **[HIGH]** KSV-0014 · Root file system is not read-only — helm/deployment.yaml:38 — Container 'cloudflared' of Deployment 'cloudflared' should set 'securityContext.readOnlyRootFilesystem' to true
- **[HIGH]** KSV-0014 · Root file system is not read-only — helm/deployment.yaml:92 — Container 'k-api' of Deployment 'k-api' should set 'securityContext.readOnlyRootFilesystem' to true
- **[HIGH]** KSV-0014 · Root file system is not read-only — helm/deployment.yaml:154 — Container 'mcp-server' of Deployment 'gemini-mcp' should set 'securityContext.readOnlyRootFilesystem' to true
- **[HIGH]** KSV-0014 · Root file system is not read-only — helm/grafana-deployment.yaml:54 — Container 'grafana' of Deployment 'grafana' should set 'securityContext.readOnlyRootFilesystem' to true
- **[HIGH]** KSV-0118 · Default security context configured — helm/deployment.yaml:38 — container cloudflared in cloudflare namespace is using the default security context
- **[HIGH]** KSV-0118 · Default security context configured — helm/deployment.yaml:154 — container gemini-mcp in default namespace is using the default security context
- **[HIGH]** KSV-0118 · Default security context configured — helm/deployment.yaml:92 — container k-api in default namespace is using the default security context
- **[HIGH]** KSV-0118 · Default security context configured — helm/deployment.yaml:36 — deployment cloudflared in cloudflare namespace is using the default security context, which allows root privileges
- **[HIGH]** KSV-0118 · Default security context configured — helm/deployment.yaml:152 — deployment gemini-mcp in default namespace is using the default security context, which allows root privileges
- **[HIGH]** KSV-0118 · Default security context configured — helm/deployment.yaml:89 — deployment k-api in default namespace is using the default security context, which allows root privileges
- **[HIGH]** KSV-0118 · Default security context configured — helm/grafana-deployment.yaml:54 — container grafana in logging namespace is using the default security context
  …and 134 more (see artifacts).

## Cloudflare posture

- • **ssl_mode** — SSL/TLS mode is 'full' (recommend 'full (strict)')
- • **always_use_https** — Always Use HTTPS is 'off'
- • **min_tls_version** — Minimum TLS version is '1.0' (recommend 1.2+)
- • **tls_1_3** — TLS 1.3 is 'on'
- • **security_level** — Security level is 'medium'
- ⚠️ **waf_custom_rules** — could not read WAF custom rules: HTTP Error 410: Gone
- ⚠️ **rate_limit_rules** — could not read rate-limit rules: HTTP Error 410: Gone
- • **ip_access_rules** — 0 IP access rules
- • **dns_a_record** — 0 A/AAAA record(s)
- • **worker_route_fail_open** — 1 route(s), 1 fail-closed (recommend fail-open)

## Remediation notes (for the Agent)

- Address CRITICAL/HIGH findings first; each artifact file in `SECURITY/artifacts/` has full details.
- Re-run the workflow manually after fixes (`Actions → Weekly Security Posture → Run workflow`).
- If a finding is a false positive, document it in this section rather than deleting it.
