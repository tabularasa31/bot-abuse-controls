#!/usr/bin/env bash
# B13 case 2 — atomic swap under load.
#
# Contract: a Channel C pull replaces the antibot_policy shared_dict
# atomically (RFC §В1: write new gen → flip meta:gen → sweep old gen).
# A reader that picks up the gen before or after the flip sees a
# consistent snapshot; the flip itself never exposes the dict in a
# half-written state.
#
# Test shape: ~20 PATCHes alternating mode active/shadow at 200ms
# intervals (≈100× the pull interval — guarantees several flips while
# the load runs), with a concurrent stream of /__policy reads. Every
# read MUST return either a parseable JSON with mode in {active,
# shadow}, never a malformed body / 5xx / connection drop.
#
# We do not assert WHICH mode each read sees — that depends on
# alignment with the pull cycle and is not the contract. The contract
# is "every read is consistent within itself", and that's what we
# check.

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/integration/lib.sh
. "$HERE/../lib.sh"

LOAD_DURATION=8       # seconds of concurrent reads
PATCH_SLEEP=0.2       # seconds between mode-flip PATCHes (bash/coreutils sleep supports decimals)
READS_PARALLEL=4      # concurrent reader processes

# --- background patcher: alternates active/shadow until killed ---
patcher() {
    local i=0
    while :; do
        if [ $((i % 2)) -eq 0 ]; then
            dash_patch '{"mode":"active"}'  >/dev/null 2>&1 || true
        else
            dash_patch '{"mode":"shadow"}' >/dev/null 2>&1 || true
        fi
        i=$((i + 1))
        sleep "$PATCH_SLEEP"
    done
}

# --- background reader: counts consistent / malformed / failed reads ---
# Output to a stats file in $TMPDIR — main process aggregates after.
reader() {
    local idx="$1"
    local stats_file="$2"
    local consistent=0 malformed=0 failed=0
    local end=$(( $(date +%s) + LOAD_DURATION ))
    while [ "$(date +%s)" -lt "$end" ]; do
        local body
        if ! body="$(edge_curl --max-time 2 "${EDGE_URL}/__policy?host=${TEST_HOST}" 2>/dev/null)"; then
            failed=$((failed + 1))
            continue
        fi
        # Match the two valid mode values explicitly; anything else
        # (no mode field / unknown value / non-JSON body) is malformed.
        if echo "$body" | grep -qE '"mode":"(active|shadow)"'; then
            consistent=$((consistent + 1))
        else
            malformed=$((malformed + 1))
            echo "  reader$idx malformed body: $body" >&2
        fi
    done
    echo "$consistent $malformed $failed" > "$stats_file"
}

# --- main ---
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Spawning patcher (${PATCH_SLEEP}s flips) + ${READS_PARALLEL} readers (${LOAD_DURATION}s)..."

patcher &
PATCHER_PID=$!

reader_pids=()
for i in $(seq 1 "$READS_PARALLEL"); do
    reader "$i" "$TMP/reader-$i.stats" &
    reader_pids+=($!)
done

# Wait for readers to finish their LOAD_DURATION window.
for pid in "${reader_pids[@]}"; do
    wait "$pid" || true
done

# Stop the patcher; ignore failure (might already be gone).
kill "$PATCHER_PID" 2>/dev/null || true
wait "$PATCHER_PID" 2>/dev/null || true

# Aggregate.
total_consistent=0
total_malformed=0
total_failed=0
for stats_file in "$TMP"/reader-*.stats; do
    read -r c m f < "$stats_file"
    total_consistent=$((total_consistent + c))
    total_malformed=$((total_malformed + m))
    total_failed=$((total_failed + f))
done

echo "  reads: ${total_consistent} consistent, ${total_malformed} malformed, ${total_failed} failed"

# Cleanup: revert to shadow.
dash_patch '{"mode":"shadow"}' >/dev/null 2>&1 || true

# Acceptance: zero malformed and zero failed reads. Consistent reads
# must be > 0 to confirm the loop actually exercised the stack.
if [ "$total_malformed" -ne 0 ]; then
    echo "FAIL: ${total_malformed} malformed reads — atomic swap leaked partial state"
    exit 1
fi
if [ "$total_failed" -ne 0 ]; then
    echo "FAIL: ${total_failed} failed reads — connection drops / 5xx during swap"
    exit 1
fi
if [ "$total_consistent" -eq 0 ]; then
    echo "FAIL: zero consistent reads — readers didn't run"
    exit 1
fi

exit 0
