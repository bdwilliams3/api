#!/usr/bin/env python3
"""Read-only Cloudflare zone posture audit.

Checks the most common Cloudflare misconfigurations and emits a JSON array of
{check, status, detail} records. Uses only the standard library.

Env:
  CLOUDFLARE_API_TOKEN  - Zone:Read + Zone Settings:Read token
  CLOUDFLARE_ZONE_ID    - optional; discovered from API_TARGET when omitted
  API_TARGET            - https://your-domain (used to discover the zone)
"""
import json
import os
import sys
import urllib.parse
import urllib.request

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
    with urllib.request.urlopen(req, timeout=30) as resp:
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


def setting(zone, sid):
    try:
        data = cf(f"/zones/{zone}/settings")
        for item in data.get("result", []):
            if item.get("id") == sid:
                return item.get("value")
    except Exception:
        return None
    return None


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

    # --- TLS / SSL -----------------------------------------------------------
    ssl_mode = setting(zone, "ssl")
    add(
        "ssl_mode",
        ssl_mode in ("full", "strict"),
        f"SSL/TLS mode is '{ssl_mode}' (recommend 'full (strict)')",
    )

    always_https = setting(zone, "always_use_https")
    add("always_use_https", always_https == "on", f"Always Use HTTPS is '{always_https}'")

    min_tls = setting(zone, "min_tls_version")
    add(
        "min_tls_version",
        min_tls in ("1.2", "1.3"),
        f"Minimum TLS version is '{min_tls}' (recommend 1.2+)",
    )

    tls13 = setting(zone, "tls_1_3")
    add("tls_1_3", tls13 == "on", f"TLS 1.3 is '{tls13}'")

    sec_level = setting(zone, "security_level")
    add(
        "security_level",
        sec_level in ("medium", "high", "under_attack"),
        f"Security level is '{sec_level}'",
    )

    # --- WAF / firewall ------------------------------------------------------
    try:
        fw = cf(f"/zones/{zone}/firewall/rules")
        rules = fw.get("result") or []
        add("waf_custom_rules", len(rules) > 0, f"{len(rules)} WAF custom rule(s)")
    except Exception as exc:
        add("waf_custom_rules", "warn", f"could not read WAF rules: {exc}")

    try:
        rl = cf(f"/zones/{zone}/rate_limits")
        rate_rules = rl.get("result") or []
        add("rate_limit_rules", len(rate_rules) > 0, f"{len(rate_rules)} rate-limit rule(s)")
    except Exception as exc:
        add("rate_limit_rules", "warn", f"could not read rate limits: {exc}")

    try:
        ar = cf(f"/zones/{zone}/firewall/access_rules/rules")
        access_rules = ar.get("result") or []
        add("ip_access_rules", len(access_rules) > 0, f"{len(access_rules)} IP access rule(s)")
    except Exception as exc:
        add("ip_access_rules", "warn", f"could not read IP access rules: {exc}")

    # --- DNS (worker bouncer needs an A/AAAA record per zone) ----------------
    try:
        dns = cf(f"/zones/{zone}/dns_records?per_page=100")
        records = dns.get("result") or []
        proxied_a = [r for r in records if r.get("type") in ("A", "AAAA")]
        cname_only = len(proxied_a) == 0
        add(
            "dns_a_record",
            not cname_only,
            f"{len(proxied_a)} A/AAAA record(s) (worker bouncer needs at least one)",
        )
    except Exception as exc:
        add("dns_a_record", "warn", f"could not read DNS records: {exc}")

    # --- Worker routes (informational) ---------------------------------------
    try:
        wr = cf(f"/zones/{zone}/workers/routes")
        routes = wr.get("result") or []
        add("worker_routes", "ok", f"{len(routes)} worker route(s)")
    except Exception as exc:
        add("worker_routes", "info", f"could not read worker routes: {exc}")

    print(json.dumps(checks, indent=2))


if __name__ == "__main__":
    main()
