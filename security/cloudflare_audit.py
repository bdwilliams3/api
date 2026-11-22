#!/usr/bin/env python3
"""Read-only Cloudflare zone posture audit.

Fetches each API resource once, checks common Cloudflare misconfigurations,
and prints a JSON array of {check, status, detail}. Stdlib only.

Env:
  CLOUDFLARE_API_TOKEN  - token with Zone:Read + Zone Settings:Read (+ optional reads)
  CLOUDFLARE_ZONE_ID    - optional; discovered from API_TARGET when omitted
  API_TARGET            - https://your-domain (used to discover the zone)
"""
import json
import os
import socket
import sys
import urllib.parse
import urllib.request

# This host's IPv6 connectivity makes urllib hang; force IPv4 for API calls.
_orig_getaddrinfo = socket.getaddrinfo


def _getaddrinfo_v4(host, port, family=socket.AF_UNSPEC, *args, **kwargs):
    return _orig_getaddrinfo(host, port, socket.AF_INET, *args, **kwargs)


socket.getaddrinfo = _getaddrinfo_v4

API = "https://api.cloudflare.com/client/v4"
TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
ZONE_ID = os.environ.get("CLOUDFLARE_ZONE_ID", "").strip()
TARGET = os.environ.get("API_TARGET", "").strip()
DOMAIN = TARGET.replace("https://", "").replace("http://", "").split("/")[0]

checks = []


def add(name, status, detail):
    checks.append({"check": name, "status": status, "detail": detail})


def cf(path):
    req = urllib.request.Request(
        API + path,
        headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def get_zone_id():
    if ZONE_ID:
        return ZONE_ID
    if not DOMAIN:
        return ""
    try:
        data = cf("/zones?name=" + urllib.parse.quote(DOMAIN))
        res = data.get("result") or []
        return res[0]["id"] if res else ""
    except Exception:
        return ""


def main():
    if not TOKEN:
        add("cloudflare", "skip", "CLOUDFLARE_API_TOKEN not set")
        print(json.dumps(checks, indent=2))
        return

    zone = get_zone_id()
    if not zone:
        add("cloudflare", "skip", "zone not found (set CLOUDFLARE_ZONE_ID or API_TARGET)")
        print(json.dumps(checks, indent=2))
        return

    # --- settings (single fetch) ---------------------------------------------
    settings = {}
    try:
        data = cf(f"/zones/{zone}/settings")
        settings = {item.get("id"): item.get("value") for item in data.get("result", [])}
    except Exception as exc:
        add("settings", "warn", f"could not read zone settings: {exc}")

    ssl_mode = settings.get("ssl")
    add("ssl_mode", ssl_mode in ("full", "strict"), f"SSL/TLS mode is '{ssl_mode}' (recommend 'full (strict)')")

    always_https = settings.get("always_use_https")
    add("always_use_https", always_https == "on", f"Always Use HTTPS is '{always_https}'")

    min_tls = settings.get("min_tls_version")
    add("min_tls_version", min_tls in ("1.2", "1.3"), f"Minimum TLS version is '{min_tls}' (recommend 1.2+)")

    tls13 = settings.get("tls_1_3")
    add("tls_1_3", tls13 == "on", f"TLS 1.3 is '{tls13}'")

    sec_level = settings.get("security_level")
    add("security_level", sec_level in ("medium", "high", "under_attack"), f"Security level is '{sec_level}'")

    # --- WAF / firewall ------------------------------------------------------
    for name, path, label in (
        ("waf_custom_rules", f"/zones/{zone}/firewall/rules", "WAF custom rules"),
        ("rate_limit_rules", f"/zones/{zone}/rate_limits", "rate-limit rules"),
        ("ip_access_rules", f"/zones/{zone}/firewall/access_rules/rules", "IP access rules"),
    ):
        try:
            res = cf(path).get("result") or []
            add(name, len(res) > 0, f"{len(res)} {label}")
        except Exception as exc:
            add(name, "warn", f"could not read {label}: {exc}")

    # --- DNS (worker bouncer needs an A/AAAA record per zone) ----------------
    try:
        records = (cf(f"/zones/{zone}/dns_records?per_page=100").get("result")) or []
        proxied_a = [r for r in records if r.get("type") in ("A", "AAAA")]
        add("dns_a_record", len(proxied_a) > 0, f"{len(proxied_a)} A/AAAA record(s)")
    except Exception as exc:
        add("dns_a_record", "warn", f"could not read DNS records: {exc}")

    # --- Worker routes (informational) ---------------------------------------
    try:
        routes = cf(f"/zones/{zone}/workers/routes").get("result") or []
        fail_closed = [r for r in routes if not r.get("request_limit_fail_open")]
        add(
            "worker_route_fail_open",
            not fail_closed,
            f"{len(routes)} route(s), {len(fail_closed)} fail-closed (recommend fail-open)",
        )
    except Exception as exc:
        add("worker_route_fail_open", "info", f"could not read worker routes: {exc}")

    print(json.dumps(checks, indent=2))


if __name__ == "__main__":
    main()
