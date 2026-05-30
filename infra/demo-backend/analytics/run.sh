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
ROTATE="${ROTATE:-$ROOT/infra/demo-stand/scripts/rotate-state.py}"
STATE="$ROOT/state"
mkdir -p "$STATE"

echo "[analytics] $(date -u +%FT%TZ) source=${BAC_SOURCE:-loki} loki=${LOKI_URL:-http://loki:3100}"

# 0) Bound lifetime-state growth (D7) BEFORE the analyze run below reads it.
# rotate-state.py archives the aged-out tail of seen-fps.json / ip-cache.json
# into state/archive/ and drops one-off probes; analyze.py lazily restores any
# key that reappears. TTLs are env-overridable (see scripts/README.md). Non-fatal
# on failure — a rotation hiccup must not block the daily report.
export STATE_FP_TTL_DAYS="${STATE_FP_TTL_DAYS:-30}"
export STATE_IP_TTL_DAYS="${STATE_IP_TTL_DAYS:-7}"
export STATE_COMPACT_MIN_COUNT="${STATE_COMPACT_MIN_COUNT:-3}"
export STATE_ARCHIVE_RETENTION_MONTHS="${STATE_ARCHIVE_RETENTION_MONTHS:-6}"
python3 "$ROTATE" || echo "[analytics] WARN rotate-state failed (non-fatal)"

# 1) Daily HTML report + email FIRST. This --html run is the one that updates the
# lifetime state (seen-fps.json / watermark / last-subject); the JSON views below
# must read that FRESH state, otherwise stale.json could flag a fp as silent that
# the current window just saw again, and the autopilot would open a bogus demote
# PR (codex P1). stderr is NOT silenced so tracebacks land in the container log.
HTML="$(mktemp)"; trap 'rm -f "$HTML"' EXIT
if python3 "$ANALYZE" --html > "$HTML"; then
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

# 2) Machine-readable views for the promotion tooling, AFTER the state update
# above. Written to temp then moved so the host autopilot never reads a
# half-written file. stderr left visible for troubleshooting.
emit() {  # <artifact-name> <analyze-args...>
  local name="$1"; shift
  if python3 "$ANALYZE" "$@" > "$STATE/.$name.tmp"; then
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

echo "[analytics] pass done"
