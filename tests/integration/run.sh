#!/usr/bin/env bash
# Integration runner: iterates cases/ and aggregates exit codes.
# Stack is expected to be up (see Makefile target test-integration) —
# this script doesn't start/stop containers, it just exercises them.
#
# Each case is a standalone shell script that:
#   - sources lib.sh (helpers + constants).
#   - exits 0 on pass, non-zero on fail.
#   - prints its own progress; the runner only frames it.

set -u  # don't `set -e` — we want to run all cases and report at the end.

HERE="$(cd "$(dirname "$0")" && pwd)"
CASES_DIR="$HERE/cases"

failed=0
total=0
passed_names=()
failed_names=()

# Cases are run in lexical order so 01-, 02-, 03-, 04- give a predictable
# sequence (later cases can depend on earlier ones leaving the stack in
# a known-good state — case 03/04 stop the backend, so they must come
# AFTER 01/02 which assume backend is up).
for case_path in "$CASES_DIR"/*.sh; do
    [ -f "$case_path" ] || continue
    case_name="$(basename "$case_path" .sh)"
    total=$((total + 1))

    echo
    echo "======================================================================"
    echo "RUN  $case_name"
    echo "======================================================================"

    if "$case_path"; then
        echo "PASS $case_name"
        passed_names+=("$case_name")
    else
        echo "FAIL $case_name"
        failed_names+=("$case_name")
        failed=$((failed + 1))
    fi
done

echo
echo "======================================================================"
echo "SUMMARY  $((total - failed))/$total passed"
if [ "${#passed_names[@]}" -gt 0 ]; then
    echo "  passed: ${passed_names[*]}"
fi
if [ "${#failed_names[@]}" -gt 0 ]; then
    echo "  failed: ${failed_names[*]}"
fi
echo "======================================================================"

exit "$failed"
