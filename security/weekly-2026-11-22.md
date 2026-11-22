# Weekly Security Posture Report — 2026-11-22

- Target: `https://sample-api.com`
- Generated: 2026-11-22 14:40 UTC

## Summary

| Source | Critical | High | Medium | Low |
|---|---|---|---|---|
| DAST (live API) | 0 | 0 | 0 | 0 |
| gosec (Go SAST) | 0 | 0 | 0 | 0 |
| Trivy (image CVEs) | 0 | 0 | 0 | 0 |
| Trivy (Docker/IaC config) | 0 | 0 | 0 | 0 |

Cloudflare posture: 0 issue(s) flagged.

## Live API scan — DAST

_No findings._

## Source code — gosec (SAST)

_No findings._

## Container image — Trivy (CVEs)

_No findings._

## Docker / compose / Helm — Trivy (misconfig)

_No findings._

## Cloudflare posture

- ✅ **ssl_mode** — SSL/TLS mode is 'full' (recommend 'full' or 'strict')
- ✅ **always_use_https** — Always Use HTTPS is 'on'
- ✅ **min_tls_version** — Minimum TLS version is '1.2' (recommend 1.2+)
- ✅ **tls_1_3** — TLS 1.3 is 'on'
- ✅ **security_level** — Security level is 'medium'
- ✅ **dns_proxied_records** — 2 proxied A/AAAA/CNAME record(s)
- ✅ **worker_route_fail_open** — 1 route(s), 0 fail-closed (recommend fail-open)

## Remediation notes (for the Agent)

- Address CRITICAL/HIGH findings first; each artifact file in `security/artifacts/` has full details.
- Re-run the ASPM container scan after fixes (`docker compose -f ~/security/docker-compose.yml exec asp /app/scan.sh`).
- If a finding is a false positive, document it in this section rather than deleting it.
