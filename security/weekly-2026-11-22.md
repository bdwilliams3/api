# Weekly Security Posture Report — 2026-11-22

- Target: `https://sample-api.com`
- Generated: 2026-11-22 14:38 UTC

## Summary

| Source | Critical | High | Medium | Low |
|---|---|---|---|---|
| DAST (live API) | 0 | 0 | 0 | 0 |
| gosec (Go SAST) | 0 | 0 | 0 | 0 |
| Trivy (image CVEs) | 0 | 0 | 0 | 0 |
| Trivy (Docker/IaC config) | 0 | 0 | 7 | 2 |

Cloudflare posture: 0 issue(s) flagged.

## Live API scan — DAST

_No findings._

## Source code — gosec (SAST)

_No findings._

## Container image — Trivy (CVEs)

_No findings._

## Docker / compose / Helm — Trivy (misconfig)

- **[MEDIUM]** KSV-0037 · User resources should not be placed in kube-system namespace — helm/metrics-server.yaml:122 — Deployment 'metrics-server' should not be set with 'kube-system' namespace
- **[MEDIUM]** KSV-0037 · User resources should not be placed in kube-system namespace — helm/metrics-server.yaml:105 — Service 'metrics-server' should not be set with 'kube-system' namespace
- **[MEDIUM]** KSV-0125 · Restrict container images to trusted registries — helm/deployment.yaml:45 — Container cloudflared in deployment cloudflared (namespace: cloudflare) uses an image from an untrusted registry.
- **[MEDIUM]** KSV-0125 · Restrict container images to trusted registries — helm/deployment.yaml:116 — Container k-api in deployment k-api (namespace: default) uses an image from an untrusted registry.
- **[MEDIUM]** KSV-0125 · Restrict container images to trusted registries — helm/deployment.yaml:202 — Container mcp-server in deployment gemini-mcp (namespace: default) uses an image from an untrusted registry.
- **[MEDIUM]** KSV-0125 · Restrict container images to trusted registries — helm/grafana-deployment.yaml:61 — Container grafana in deployment grafana (namespace: logging) uses an image from an untrusted registry.
- **[MEDIUM]** KSV-0125 · Restrict container images to trusted registries — helm/metrics-server.yaml:141 — Container metrics-server in deployment metrics-server (namespace: kube-system) uses an image from an untrusted registry.
- **[LOW]** KSV-0110 · Workloads in the default namespace — helm/deployment.yaml:180 — deployment gemini-mcp in default namespace should set metadata.namespace to a non-default namespace
- **[LOW]** KSV-0110 · Workloads in the default namespace — helm/deployment.yaml:89 — deployment k-api in default namespace should set metadata.namespace to a non-default namespace

## Cloudflare posture

- ✅ **ssl_mode** — SSL/TLS mode is 'full' (recommend 'full' or 'strict')
- ✅ **always_use_https** — Always Use HTTPS is 'on'
- ✅ **min_tls_version** — Minimum TLS version is '1.2' (recommend 1.2+)
- ✅ **tls_1_3** — TLS 1.3 is 'on'
- ✅ **security_level** — Security level is 'medium'
- ✅ **dns_proxied_records** — 2 proxied A/AAAA/CNAME record(s)
- ✅ **worker_route_fail_open** — 1 route(s), 0 fail-closed (recommend fail-open)

## Remediation notes (for the Agent)

- Address CRITICAL/HIGH findings first; each artifact file in `SECURITY/artifacts/` has full details.
- Re-run the workflow manually after fixes (`Actions → Weekly Security Posture → Run workflow`).
- If a finding is a false positive, document it in this section rather than deleting it.
