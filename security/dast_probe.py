#!/usr/bin/env python3
"""Lightweight DAST probe for k-api (stdlib only, no external scanner).

Checks the sensitive/backup/config/token paths most likely to be exposed on a
Go/gin API, plus baseline security headers. Prints a JSON array of
{severity, title, detail} — consumed by aggregate_report.py.

Env:
  ASP_TARGET  - base URL to scan (default http://host.docker.internal:8080)
"""
import json
import os
import socket
import urllib.error
import urllib.request

# This host's IPv6 connectivity makes urllib hang; force IPv4.
_orig_getaddrinfo = socket.getaddrinfo


def _getaddrinfo_v4(host, port, family=socket.AF_UNSPEC, *args, **kwargs):
    return _orig_getaddrinfo(host, port, socket.AF_INET, *args, **kwargs)


socket.getaddrinfo = _getaddrinfo_v4

TARGET = os.environ.get("ASP_TARGET", "http://host.docker.internal:8080").rstrip("/")

# Backup/config/token/log patterns (matches the probes seen in k-api's own
# logs) + common Go/gin debug & docs paths.
PATHS = [
    "/.git/config", "/.git/HEAD", "/.env", "/.env.local",
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/sample-api.zip", "/sample-api.tar.gz", "/sample-api.sql", "/sample-api.bak",
    "/sample-api_2026.sql", "/sample-api-2025.zip",
    "/config", "/config.json", "/config.yml", "/config.yaml",
    "/.config", "/settings", "/secrets", "/.secrets",
    "/swagger", "/swagger.json", "/swagger/index.html", "/api/docs", "/openapi.json",
    "/debug/pprof/", "/debug/pprof/cmdline", "/metrics", "/healthz",
    "/admin", "/actuator", "/actuator/health",
    "/wp-content/uploads/sample-api.sql", "/.well-known/security.txt",
]

findings = []


def probe(url):
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "k-api-asp"})
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            return resp.status, dict(resp.headers), resp.read(2000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(2000).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return None, {}, str(e)


for path in PATHS:
    code, headers, body = probe(TARGET + path)
    if code is None:
        continue
    if code == 200:
        findings.append(
            {
                "severity": "medium",
                "title": f"Sensitive path exposed: {path}",
                "detail": f"GET {path} returned 200. Body preview: {body[:120]!r}",
            }
        )
    elif code in (301, 302, 307, 308):
        findings.append(
            {
                "severity": "low",
                "title": f"Redirect on {path}",
                "detail": f"GET {path} returned {code} -> {headers.get('Location', '?')}",
            }
        )

# Baseline security headers on /health
code, headers, _ = probe(TARGET + "/health")
if code == 200:
    present = {k.lower() for k in headers}
    for header in (
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "Referrer-Policy",
    ):
        if header.lower() not in present:
            findings.append(
                {
                    "severity": "low",
                    "title": f"Missing security header: {header}",
                    "detail": f"/health response is missing the {header} header",
                }
            )

print(json.dumps(findings, indent=2))
