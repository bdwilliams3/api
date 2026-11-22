#!/usr/bin/env python3
"""Aggregate scanner artifacts into SECURITY/weekly-<date>.md and SECURITY/LATEST.md.

Inputs (all optional, missing files are treated as "no findings"):
  SECURITY/artifacts/nuclei.jsonl       - Nuclei DAST (JSON lines)
  SECURITY/artifacts/gosec.json         - gosec SAST  ({"Issues": [...]})
  SECURITY/artifacts/trivy-image.json   - Trivy image scan
  SECURITY/artifacts/trivy-config.json  - Trivy IaC/config scan
  SECURITY/artifacts/cloudflare.json    - Cloudflare posture audit (JSON array)
"""
import json
import os
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART = os.path.join(ROOT, "SECURITY", "artifacts")
OUT = os.path.join(ROOT, "SECURITY")
DATE = datetime.now(timezone.utc).strftime("%Y-%m-%d")

TARGET = os.environ.get("API_TARGET", "https://sample-api.com")

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def load_jsonl(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def sev_key(s):
    return SEV_ORDER.get(str(s or "unknown").lower(), 5)


def count_by_severity(findings):
    """findings: list of dicts with a 'severity' key."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = str(f.get("severity", "info")).lower()
        counts[s] = counts.get(s, 0) + 1
    return counts


def short(text, n=240):
    text = str(text or "").replace("\n", " ").strip()
    return text if len(text) <= n else text[: n - 1] + "…"


# ---- collect findings -------------------------------------------------------
nuclei = []
for item in load_jsonl(os.path.join(ART, "nuclei.jsonl")):
    info = item.get("info") or {}
    nuclei.append(
        {
            "severity": info.get("severity", "unknown"),
            "title": info.get("name") or item.get("template-id", "nuclei finding"),
            "detail": "`{tid}` matched at `{where}` — {desc}".format(
                tid=item.get("template-id", "?"),
                where=item.get("matched-at") or item.get("host", "?"),
                desc=short(info.get("description") or info.get("tags") or ""),
            ),
        }
    )

gosec = []
gosec_doc = load_json(os.path.join(ART, "gosec.json")) or {}
for issue in gosec_doc.get("Issues", []) or []:
    gosec.append(
        {
            "severity": issue.get("severity", "unknown"),
            "title": issue.get("rule_id", "gosec"),
            "detail": "{file}:{line} — {details} (code: {code})".format(
                file=issue.get("file", "?"),
                line=issue.get("line", "?"),
                details=short(issue.get("details") or issue.get("code") or ""),
                code=short(issue.get("code") or ""),
            ),
        }
    )

trivy_image = []
trivy_img_doc = load_json(os.path.join(ART, "trivy-image.json")) or {}
for result in trivy_img_doc.get("Results", []) or []:
    for v in result.get("Vulnerabilities", []) or []:
        trivy_image.append(
            {
                "severity": v.get("Severity", "unknown"),
                "title": "{id} · {pkg} {inst} → {fix}".format(
                    id=v.get("VulnerabilityID", "?"),
                    pkg=v.get("PkgName", "?"),
                    inst=v.get("InstalledVersion", "?"),
                    fix=v.get("FixedVersion", "n/a"),
                ),
                "detail": "{target} — {title}".format(
                    target=result.get("Target", "?"), title=short(v.get("Title") or "")
                ),
            }
        )

trivy_config = []
trivy_cfg_doc = load_json(os.path.join(ART, "trivy-config.json")) or {}
for result in trivy_cfg_doc.get("Results", []) or []:
    for m in result.get("Misconfigurations", []) or []:
        cause = m.get("CauseMetadata") or {}
        trivy_config.append(
            {
                "severity": m.get("Severity", "unknown"),
                "title": "{id} · {title}".format(id=m.get("ID", "?"), title=m.get("Title", "?")),
                "detail": "{target}{line} — {msg}".format(
                    target=result.get("Target", "?"),
                    line=f":{cause.get('StartLine')}" if cause.get("StartLine") else "",
                    msg=short(m.get("Message") or m.get("Description") or ""),
                ),
            }
        )

cloudflare = load_json(os.path.join(ART, "cloudflare.json")) or []

for group in (nuclei, gosec, trivy_image, trivy_config):
    group.sort(key=lambda f: (sev_key(f["severity"]), f["title"].lower()))

# ---- render -----------------------------------------------------------------
lines = []
lines.append(f"# Weekly Security Posture Report — {DATE}")
lines.append("")
lines.append(f"- Target: `{TARGET}`")
lines.append(f"- Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
lines.append("")

# Summary table
def cell(n):
    return str(n) if n else "0"

lines.append("## Summary")
lines.append("")
lines.append("| Source | Critical | High | Medium | Low |")
lines.append("|---|---|---|---|---|")
for name, group in (
    ("Nuclei (live API DAST)", nuclei),
    ("gosec (Go SAST)", gosec),
    ("Trivy (image CVEs)", trivy_image),
    ("Trivy (Docker/IaC config)", trivy_config),
):
    c = count_by_severity(group)
    lines.append(
        f"| {name} | {cell(c['critical'])} | {cell(c['high'])} | {cell(c['medium'])} | {cell(c['low'])} |"
    )
lines.append("")

cloudflare_fail = [c for c in cloudflare if c.get("status") in ("fail", "warn")]
lines.append(f"Cloudflare posture: {len(cloudflare_fail)} issue(s) flagged.")
lines.append("")


def section(title, findings, limit=20):
    lines.append(f"## {title}")
    lines.append("")
    if not findings:
        lines.append("_No findings._")
    else:
        for f in findings[:limit]:
            lines.append(f"- **[{f['severity'].upper()}]** {f['title']} — {short(f['detail'])}")
        if len(findings) > limit:
            lines.append(f"  …and {len(findings) - limit} more (see artifacts).")
    lines.append("")


section("Live API scan — Nuclei (DAST)", nuclei)
section("Source code — gosec (SAST)", gosec)
section("Container image — Trivy (CVEs)", trivy_image)
section("Docker / compose / Helm — Trivy (misconfig)", trivy_config)

lines.append("## Cloudflare posture")
lines.append("")
if not cloudflare:
    lines.append("_No Cloudflare audit data (token or zone not configured)._")
else:
    for c in cloudflare:
        icon = {"ok": "✅", "fail": "❌", "warn": "⚠️", "skip": "⏭️", "info": "ℹ️"}.get(
            c.get("status"), "•"
        )
        lines.append(f"- {icon} **{c.get('check')}** — {c.get('detail')}")
lines.append("")

lines.append("## Remediation notes (for the Agent)")
lines.append("")
lines.append("- Address CRITICAL/HIGH findings first; each artifact file in `SECURITY/artifacts/` has full details.")
lines.append("- Re-run the workflow manually after fixes (`Actions → Weekly Security Posture → Run workflow`).")
lines.append("- If a finding is a false positive, document it in this section rather than deleting it.")
lines.append("")

report = "\n".join(lines)

os.makedirs(OUT, exist_ok=True)
weekly_path = os.path.join(OUT, f"weekly-{DATE}.md")
latest_path = os.path.join(OUT, "LATEST.md")
with open(weekly_path, "w", encoding="utf-8") as f:
    f.write(report)
with open(latest_path, "w", encoding="utf-8") as f:
    f.write(report)

print(f"Wrote {weekly_path} and {latest_path}")
