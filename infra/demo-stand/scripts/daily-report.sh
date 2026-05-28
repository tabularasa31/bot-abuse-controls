#!/usr/bin/env bash
# Daily report for the abuse-controls demo stand (resty).
# Cron: 0 8 * * * /home/ubuntu/abuse-controls/infra/demo-stand/scripts/daily-report.sh
#
# Generates a Russian-language HTML report from the stand's BAC_LOG json,
# archives a markdown copy under <repo>/reports/, emails the HTML via
# msmtp + Gmail SMTP. State/reports live under the repo root.

set -euo pipefail

# Repo root = three levels up from this script (infra/demo-stand/scripts).
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYZE="${HERE}/analyze.py"
ROOT="${ABUSE_CONTROLS_ROOT:-$(cd "${HERE}/../../.." && pwd)}"

# Local, gitignored env. Two files, sourced in order:
#   .env         — deploy vars (DEMO_BIND_IP, EDGE_ID, Channel C). A
#                  `> .env` rewrite on redeploy can clobber anything
#                  written here.
#   .env.report  — report addresses (REPORT_FROM/REPORT_TO). Kept SEPARATE
#                  precisely so a clobbering `> .env` can't drop them; no
#                  doc or deploy step ever rewrites this file. Sourced last
#                  so it wins. Both are gitignored — addresses aren't
#                  committed.
for ENV_FILE in "${HERE}/../.env" "${HERE}/../.env.report"; do
    if [ -f "${ENV_FILE}" ]; then
        set -a
        # shellcheck source=/dev/null
        . "${ENV_FILE}"
        set +a
    fi
done

HTML=$(mktemp)
trap 'rm -f "${HTML}"' EXIT

# One invocation: the full --html run also caches the subject line to
# state/last-subject.txt, so we don't re-fetch docker logs for it.
python3 "${ANALYZE}" --html > "${HTML}"
SUBJECT=$(cat "${ROOT}/state/last-subject.txt" 2>/dev/null || echo "[abuse-controls] daily report")

# Addresses come from infra/demo-stand/.env.report (gitignored) — neither
# is committed:
#   REPORT_FROM = sender; must match the authenticated msmtp account so
#                 Gmail SPF/DKIM passes. If unset, msmtp fills the From
#                 header from its own config (~/.msmtprc).
#   REPORT_TO   = recipient (the routine's Gmail mailbox); falls back to
#                 REPORT_FROM.
REPORT_FROM="${REPORT_FROM:-}"
REPORT_TO="${REPORT_TO:-$REPORT_FROM}"
if [ -z "${REPORT_TO}" ]; then
    echo "daily-report: REPORT_TO unset — set REPORT_TO (and REPORT_FROM) in ${HERE}/../.env.report" >&2
    exit 1
fi

{
    if [ -n "${REPORT_FROM}" ]; then echo "From: ${REPORT_FROM}"; fi
    echo "To: ${REPORT_TO}"
    echo "Subject: ${SUBJECT}"
    echo "MIME-Version: 1.0"
    echo "Content-Type: text/html; charset=utf-8"
    echo
    cat "${HTML}"
} | msmtp "${REPORT_TO}"
