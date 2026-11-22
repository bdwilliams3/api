#!/usr/bin/env bash
# Local ASPM scan (no CI/CD): DAST (nuclei) + SAST (gosec) + image/config
# (trivy) + Cloudflare audit -> SECURITY/weekly-*.md -> commit to repo -> email.
# Schedule weekly via Windows Task Scheduler (see README at ~/security).
set -euo pipefail

export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."           # repo root
REPO="$PWD"
API_TARGET="${API_TARGET:-https://sample-api.com}"
ART="$REPO/SECURITY/artifacts"
mkdir -p "$ART"

# ---- config (reuse the SIEM .env) ------------------------------------------
SIEM_ENV="${SIEM_ENV:-$HOME/security/.env}"
get() { grep -E "^$1=" "$SIEM_ENV" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"'; }

CF_TOKEN="$(get CF_BOUNCER_TOKEN)"
[[ -z "$CF_TOKEN" ]] && CF_TOKEN="$(grep -E '^CLOUDFLARE_API_TOKEN=' "$HOME/.env" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"')"

export CLOUDFLARE_API_TOKEN="$CF_TOKEN"
export CLOUDFLARE_ZONE_ID="$(get CF_ZONE_ID)"
export API_TARGET
export SMTP_HOST="$(get SMTP_HOST)"
export SMTP_PORT="$(get SMTP_PORT)"
export SMTP_USER="$(get SMTP_USER)"
export SMTP_PASS="$(get SMTP_PASS)"
export SMTP_TO="$(get SMTP_TO)"

CACHE="$HOME/security/asp/cache"
mkdir -p "$CACHE/trivy"

# ---- 1. Nuclei DAST ---------------------------------------------------------
echo "[1/6] Nuclei DAST -> $API_TARGET"
docker run --rm \
  -v "$(cygpath -w "$ART"):/out" \
  projectdiscovery/nuclei:latest \
  -u "$API_TARGET" \
  -tags exposure,misconfig,cve,tech \
  -severity low,medium,high,critical \
  -rate-limit 5 -bulk-size 10 -c 10 -timeout 10 \
  -jsonl -silent -o /out/nuclei.jsonl || true

# ---- 2. gosec SAST ----------------------------------------------------------
echo "[2/6] gosec SAST"
GOSEC="$(cygpath -u "$(go env GOPATH)/bin/gosec.exe")"
if [[ ! -f "$GOSEC" ]]; then
  echo "  installing gosec..."
  go install github.com/securego/gosec/v2/cmd/gosec@latest
fi
"$GOSEC" -no-fail -fmt=json -out "$ART/gosec.json" ./... || true

# ---- 3. Trivy image scan ----------------------------------------------------
echo "[3/6] Trivy image scan"
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(cygpath -w "$CACHE/trivy"):/root/.cache" \
  -v "$(cygpath -w "$ART"):/out" \
  aquasec/trivy:latest image --quiet --scanners vuln --format json \
  --output /out/trivy-image.json ghcr.io/bdwilliams3/api:latest || true

# ---- 4. Trivy config scan ---------------------------------------------------
echo "[4/6] Trivy config scan"
docker run --rm \
  -v "$(cygpath -w "$CACHE/trivy"):/root/.cache" \
  -v "$(cygpath -w "$REPO"):/src" \
  -v "$(cygpath -w "$ART"):/out" \
  aquasec/trivy:latest config --quiet --format json \
  --output /out/trivy-config.json /src || true

# ---- 5. Cloudflare posture audit --------------------------------------------
echo "[5/6] Cloudflare posture audit"
python security/cloudflare_audit.py > "$ART/cloudflare.json" || true

# ---- 6. Aggregate -----------------------------------------------------------
echo "[6/6] Aggregate report"
python security/aggregate_report.py

# ---- commit report to repo --------------------------------------------------
git add -f SECURITY/*.md
if ! git diff --cached --quiet; then
  git -c user.name="security-bot" -c user.email="security-bot@users.noreply.github.com" \
    commit -m "chore(security): weekly posture report $(date -u +%F)"
  git push origin master || true
fi

# ---- email (skips if SMTP_* unset) ------------------------------------------
python security/send_email.py || true

echo "ASPM scan complete."
