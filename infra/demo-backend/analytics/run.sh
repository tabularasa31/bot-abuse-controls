#!/usr/bin/env bash
# One analytics pass for the antibot-analytics container: read Loki, write the
# JSON artifacts the promotion tooling consumes, render + email the daily report.
#
# Runs INSIDE the antibot-backend compose network so it can reach Loki at
# http://loki:3100 (the read API is in-network only). The artifacts land in
# $ABUSE_CONTROLS_ROOT/state, which is bind-mounted back to the repo checkout so
# the host-side promote/demote/autopilot scripts read the same files.
#
# This producer never touches git/gh — turning artifacts into PRs is the host
# autopilot's job (needs the checkout + gh creds, kept off this container).
set -uo pipefail
ROOT="${ABUSE_CONTROLS_ROOT:-/data}"
ANALYZE="${ANALYZE:-$ROOT/infra/demo-stand/scripts/analyze.py}"
STATE="$ROOT/state"
mkdir -p "$STATE"

echo "[analytics] $(date -u +%FT%TZ) source=${BAC_SOURCE:-loki} loki=${LOKI_URL:-http://loki:3100}"

# Machine-readable views for the promotion tooling. Written to temp then moved
# so the host autopilot never reads a half-written file.
emit() {  # <artifact-name> <analyze-args...>
  local name="$1"; shift
  if python3 "$ANALYZE" "$@" > "$STATE/.$name.tmp" 2>/dev/null; then
    mv "$STATE/.$name.tmp" "$STATE/$name"
    echo "[analytics] wrote state/$name"
  else
    rm -f "$STATE/.$name.tmp"
    echo "[analytics] WARN failed to write state/$name"
  fi
}
emit candidates.json          --candidates-json
emit stale.json               --stale-blocklist-json --ttl-days "${BAC_TTL_DAYS:-14}"
emit staging-observation.json --staging-observation-json --min-staging-hours "${BAC_MIN_STAGING_HOURS:-48}"

# Daily HTML report + email (msmtp), mirroring the old edge daily-report.sh.
HTML="$(mktemp)"; trap 'rm -f "$HTML"' EXIT
if python3 "$ANALYZE" --html > "$HTML" 2>/dev/null; then
  SUBJECT="$(cat "$STATE/last-subject.txt" 2>/dev/null || echo '[abuse-controls] daily report')"
  REPORT_FROM="${REPORT_FROM:-}"; REPORT_TO="${REPORT_TO:-$REPORT_FROM}"
  # Build the msmtp config from env (secrets stay in .env, never in the image).
  MSMTP=(msmtp)
  if [ -n "${MSMTP_HOST:-}" ]; then
    cat > /tmp/msmtprc <<EOF
account default
host ${MSMTP_HOST}
port ${MSMTP_PORT:-587}
auth on
user ${MSMTP_USER:-$REPORT_FROM}
password ${MSMTP_PASS:-}
tls on
tls_starttls on
from ${REPORT_FROM}
EOF
    chmod 600 /tmp/msmtprc
    MSMTP=(msmtp --file=/tmp/msmtprc)
  fi
  if [ -n "$REPORT_TO" ] && command -v msmtp >/dev/null 2>&1; then
    {
      [ -n "$REPORT_FROM" ] && echo "From: ${REPORT_FROM}"
      echo "To: ${REPORT_TO}"
      echo "Subject: ${SUBJECT}"
      echo "MIME-Version: 1.0"
      echo "Content-Type: text/html; charset=utf-8"
      echo
      cat "$HTML"
    } | "${MSMTP[@]}" "${REPORT_TO}" && echo "[analytics] emailed report to ${REPORT_TO}" \
      || echo "[analytics] WARN msmtp send failed"
  else
    echo "[analytics] email skipped (REPORT_TO unset or msmtp absent)"
  fi
else
  echo "[analytics] WARN report render failed"
fi
echo "[analytics] pass done"
