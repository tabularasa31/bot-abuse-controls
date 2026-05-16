#!/usr/bin/env bash
# Analyse shadow-mode antibot logs. Reads ANTIBOT_EVENT JSON lines from
# `docker logs nginx-shadow` (or any file you redirect them to) and runs
# a set of canned aggregations.
#
# Usage:
#   ./analyze-shadow-log.sh                  # reads from `docker logs`
#   ./analyze-shadow-log.sh /path/to/log     # reads from file
#   ./analyze-shadow-log.sh - < events.json  # reads from stdin
#
# Each section is independent — comment out the ones you don't want.

set -euo pipefail

src="${1:-docker}"

events() {
    case "${src}" in
        docker) docker logs nginx-shadow 2>&1 ;;
        -)      cat ;;
        *)      cat "${src}" ;;
    esac \
        | grep --line-buffered "ANTIBOT_EVENT " \
        | sed -E 's/.*ANTIBOT_EVENT (\{.*\}).*/\1/'
    # ↑ The sed strips both the prefix (timestamp, nginx headers) and
    # the suffix nginx appends in log_by_lua phase (" while logging
    # request, client: ..."). Greedy {.*} match grabs only the JSON.
}

if ! command -v jq >/dev/null; then
    echo "jq is required: brew install jq / apt install jq" >&2
    exit 1
fi

# Materialise once into a temp file so each section doesn't re-read docker.
tmp=$(mktemp)
trap "rm -f ${tmp}" EXIT
events > "${tmp}"

total=$(wc -l < "${tmp}" | tr -d ' ')
if [ "${total}" -eq 0 ]; then
    echo "No ANTIBOT_EVENT lines found in source: ${src}" >&2
    exit 1
fi

echo "============================================================"
echo "Shadow-mode antibot log summary  (${total} events)"
echo "============================================================"
echo

echo "## Verdict distribution (would_verdict)"
echo "------------------------------------------------------------"
jq -r '.would_verdict' "${tmp}" | sort | uniq -c | sort -rn
echo

echo "## Cache hit ratio"
echo "------------------------------------------------------------"
jq -r '.cache_hit | tostring' "${tmp}" | sort | uniq -c
echo

echo "## Top 20 fingerprints by request count"
echo "------------------------------------------------------------"
# Cipher count is encoded in fp prefix at positions 4-5 (after "L<ver><sni>"),
# e.g. "L13d49h2_..." → 49. log_event.lua truncates the raw cipher list to
# 256 bytes for log size, so we can't recover it from fp_cipher_list here.
jq -r '"\(.fp)\t\(.fp | .[4:6])"' "${tmp}" \
    | sort | uniq -c | sort -rn | head -20 \
    | awk 'BEGIN{printf "%8s  %-50s %s\n", "count", "fp", "ciphers"} {printf "%8s  %-50s %s\n", $1, $2, $3}'
echo

echo "## Top 10 UA strings by request count (truncated to 80 chars)"
echo "------------------------------------------------------------"
jq -r '.ua // "(no UA)"' "${tmp}" \
    | sort | uniq -c | sort -rn | head -10 \
    | awk '{ua=""; for (i=2; i<=NF; i++) ua = ua " " $i; printf "%8s %s\n", $1, substr(ua, 1, 80)}'
echo

echo "## Would-be blocks by UA family heuristic"
echo "------------------------------------------------------------"
echo "(UA strings matching curl|python|Go|wget|bot|crawler|scrape patterns, only would_verdict=block)"
jq -r 'select(.would_verdict == "block") | .ua' "${tmp}" \
    | grep -iE 'curl|python|go-http|wget|bot|crawler|scrape|spider' \
    | sort | uniq -c | sort -rn | head -10
echo

echo "## Fp cardinality over time (events per minute, distinct fp per minute)"
echo "------------------------------------------------------------"
# Use `date` for timestamp formatting — POSIX awk on macOS doesn't have
# strftime. One date invocation per minute-bucket, which is cheap.
jq -r '"\(.ts | floor / 60 | floor)\t\(.fp)"' "${tmp}" \
    | awk -F'\t' '{count[$1]++; if (!seen[$1,$2]++) distinct[$1]++}
                  END { for (m in count) printf "%d\t%d\t%d\n", m, count[m], distinct[m] }' \
    | sort -n \
    | while read -r minute events distinct_fp; do
        ts=$(date -r $((minute * 60)) "+%Y-%m-%d %H:%M" 2>/dev/null \
             || date -d @$((minute * 60)) "+%Y-%m-%d %H:%M" 2>/dev/null \
             || echo "(minute ${minute})")
        printf '%s\tevents=%d\tdistinct_fp=%d\n' "${ts}" "${events}" "${distinct_fp}"
      done | tail -20
echo

echo "## Possible UA↔JA mismatches (would-be A5 signal)"
echo "------------------------------------------------------------"
echo "(Chrome/Firefox/Safari UAs paired with non-browser-like cipher counts)"
echo "Browser UA + cipher_count in {15,16,20} = expected"
echo "Browser UA + cipher_count outside that range = suspicious"
jq -r 'select(.ua | test("Chrome|Firefox|Safari"; "i"))
       | "\(.ua | match("(Chrome|Firefox|Safari)"; "i").string)\t\(.fp | .[4:6])\t\(.fp)"' "${tmp}" \
    | awk -F'\t' '{
        cc = $2 + 0
        expected = (cc == 15 || cc == 16 || cc == 20)
        if (!expected) print "  SUSPICIOUS:", $1, "ciphers="$2, "fp="$3
      }' | sort -u | head -20 || true
echo

echo "## Latency percentiles (request_time_ms — full proxied request)"
echo "------------------------------------------------------------"
jq -r '.request_time_ms' "${tmp}" | sort -n \
    | awk '{a[NR]=$1} END {
        printf "  p50:  %.2f ms\n", a[int(NR*0.50)]
        printf "  p75:  %.2f ms\n", a[int(NR*0.75)]
        printf "  p90:  %.2f ms\n", a[int(NR*0.90)]
        printf "  p99:  %.2f ms\n", a[int(NR*0.99)]
        printf "  max:  %.2f ms\n", a[NR]
      }'
echo

echo "============================================================"
echo "Done. Re-run after a few hours of traffic for a fuller picture."
echo "============================================================"
