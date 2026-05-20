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

HTML=$(mktemp)
trap 'rm -f "${HTML}"' EXIT

# One invocation: the full --html run also caches the subject line to
# state/last-subject.txt, so we don't re-fetch docker logs for it.
python3 "${ANALYZE}" --html > "${HTML}"
SUBJECT=$(cat "${ROOT}/state/last-subject.txt" 2>/dev/null || echo "[abuse-controls] daily report")

REPORT_FROM=${REPORT_FROM:-reports@example.com}
REPORT_TO=${REPORT_TO:-reports@example.com}

{
    echo "From: ${REPORT_FROM}"
    echo "To: ${REPORT_TO}"
    echo "Subject: ${SUBJECT}"
    echo "MIME-Version: 1.0"
    echo "Content-Type: text/html; charset=utf-8"
    echo
    cat "${HTML}"
} | msmtp "${REPORT_TO}"
