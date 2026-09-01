#!/usr/bin/env bash
# seed-catalogs-from-db.sh — a one-off migration of the slow-catalog contents
# from Postgres into the catalogs/*.yaml files. Run it BEFORE `alembic upgrade head`
# (migration 0004 drops the tables). Afterwards review `git diff
# catalogs/`, commit the seed and apply the migration.
#
# Usage:
#   POSTGRES_DSN="postgres://user:pass@host:5432/db" \
#     ./scripts/seed-catalogs-from-db.sh [out_dir]
#
# out_dir defaults to ./catalogs (relative to the current pwd).
#
# Requires psql.
#
# The script writes the YAML by hand (with no dependency on Go or a yaml generator), to
# avoid introducing new build artifacts. The format is symmetric with what
# internal/filesource expects (see docs/architecture-decisions/006).

set -euo pipefail

OUT_DIR="${1:-./catalogs}"

if [[ -z "${POSTGRES_DSN:-}" ]]; then
  echo "POSTGRES_DSN is not set" >&2
  exit 2
fi

if [[ ! -d "$OUT_DIR" ]]; then
  echo "$OUT_DIR not found — create the directory first (git checkout main && cd repo root)" >&2
  exit 2
fi

psql_q() {
  # -At: tuples-only, unaligned. -F'<TAB>': field separator. -X: do not read .psqlrc.
  PGOPTIONS="--client-min-messages=warning" \
    psql "$POSTGRES_DSN" -X -At -F$'\t' -c "$1"
}

# version: singleton.
VERSION=$(psql_q "SELECT version FROM catalog_version WHERE id = 1")
if [[ -n "$VERSION" ]]; then
  echo "$VERSION" > "$OUT_DIR/version"
  echo "wrote $OUT_DIR/version: $VERSION"
fi

# Keys and values are quoted as YAML single-quoted scalars: inside
# single quotes YAML only escapes the ' itself, as ''. Awk's %q
# is not portable (gawk 4.2+ only) and escapes for the shell, not for YAML —
# so we do it in bash. PR-59 review (gemini high / codex P1).
yaml_sq() {
  # echo a single-quoted YAML scalar for the string $1.
  local s=${1//\'/\'\'}
  printf "'%s'" "$s"
}

# tls_fp_blocklist: map fp → status. The legacy DB table from 0001_init.sql
# is called `fp_blocklist` (migration 0004 drops it); the output file is
# `tls_fp_blocklist.yaml` (the name from vision/entities-reference.md, PR-62 rename).
# The script runs BEFORE 0004, so the SQL reads the old name.
{
  echo "# tls_fp_blocklist.yaml — seeded from DB at $(date -u +%FT%TZ)."
  echo "# Format: <fp>: <status>"
  psql_q "SELECT fp, status FROM fp_blocklist ORDER BY fp" \
    | while IFS=$'\t' read -r key status; do
        [[ -z "$key" ]] && continue
        # Trim whitespace and CR (Windows-edited rows, manual UPDATEs):
        # the bash builtin does not trim without extglob, so we use parameter
        # expansion. Otherwise ' ' / '\r' pass the guard as "non-empty"
        # and land in the YAML as an invalid status → catalog.Validate
        # rejects the whole slow layer on the reloader tick (PR-62 round-6).
        status="${status#"${status%%[![:space:]]*}"}"
        status="${status%"${status##*[![:space:]]}"}"
        if [[ "$status" != "active" && "$status" != "staging" ]]; then
          printf "# %s: <status from DB was %q, fill manually with active|staging>\n" \
            "$(yaml_sq "$key")" "$status"
          echo "WARN: $key has invalid status \"$status\" in DB — written as comment, fix manually before merge" >&2
          continue
        fi
        printf "%s: %s\n" "$(yaml_sq "$key")" "$status"
      done
} > "$OUT_DIR/tls_fp_blocklist.yaml"
echo "wrote $OUT_DIR/tls_fp_blocklist.yaml"

# ua_blacklist: map pattern → status. A pattern contains regex metacharacters —
# a YAML single-quoted scalar delivers them uninterpreted.
{
  echo "# ua_blacklist.yaml — seeded from DB at $(date -u +%FT%TZ)."
  echo "# Format: <pattern>: <status>"
  psql_q "SELECT pattern, status FROM ua_blacklist ORDER BY pattern" \
    | while IFS=$'\t' read -r key status; do
        [[ -z "$key" ]] && continue
        # Trim whitespace and CR (Windows-edited rows, manual UPDATEs):
        # the bash builtin does not trim without extglob, so we use parameter
        # expansion. Otherwise ' ' / '\r' pass the guard as "non-empty"
        # and land in the YAML as an invalid status → catalog.Validate
        # rejects the whole slow layer on the reloader tick (PR-62 round-6).
        status="${status#"${status%%[![:space:]]*}"}"
        status="${status%"${status##*[![:space:]]}"}"
        if [[ "$status" != "active" && "$status" != "staging" ]]; then
          printf "# %s: <status from DB was %q, fill manually with active|staging>\n" \
            "$(yaml_sq "$key")" "$status"
          echo "WARN: $key has invalid status \"$status\" in DB — written as comment, fix manually before merge" >&2
          continue
        fi
        printf "%s: %s\n" "$(yaml_sq "$key")" "$status"
      done
} > "$OUT_DIR/ua_blacklist.yaml"
echo "wrote $OUT_DIR/ua_blacklist.yaml"

# ip_blocklist: map cidr → status.
{
  echo "# ip_blocklist.yaml — seeded from DB at $(date -u +%FT%TZ)."
  echo "# Format: <cidr>: <status>"
  psql_q "SELECT cidr, status FROM ip_blocklist ORDER BY cidr" \
    | while IFS=$'\t' read -r key status; do
        [[ -z "$key" ]] && continue
        # Trim whitespace and CR (Windows-edited rows, manual UPDATEs):
        # the bash builtin does not trim without extglob, so we use parameter
        # expansion. Otherwise ' ' / '\r' pass the guard as "non-empty"
        # and land in the YAML as an invalid status → catalog.Validate
        # rejects the whole slow layer on the reloader tick (PR-62 round-6).
        status="${status#"${status%%[![:space:]]*}"}"
        status="${status%"${status##*[![:space:]]}"}"
        if [[ "$status" != "active" && "$status" != "staging" ]]; then
          printf "# %s: <status from DB was %q, fill manually with active|staging>\n" \
            "$(yaml_sq "$key")" "$status"
          echo "WARN: $key has invalid status \"$status\" in DB — written as comment, fix manually before merge" >&2
          continue
        fi
        printf "%s: %s\n" "$(yaml_sq "$key")" "$status"
      done
} > "$OUT_DIR/ip_blocklist.yaml"
echo "wrote $OUT_DIR/ip_blocklist.yaml"

# ip_whitelist: sequence of cidr.
{
  echo "# ip_whitelist.yaml — seeded from DB at $(date -u +%FT%TZ)."
  psql_q "SELECT cidr FROM ip_whitelist ORDER BY cidr" \
    | while IFS= read -r cidr; do
        [[ -z "$cidr" ]] && continue
        printf -- "- %s\n" "$(yaml_sq "$cidr")"
      done
} > "$OUT_DIR/ip_whitelist.yaml"
echo "wrote $OUT_DIR/ip_whitelist.yaml"

# asn_datacenters: sequence of uint32.
{
  echo "# asn_datacenters.yaml — seeded from DB at $(date -u +%FT%TZ)."
  psql_q "SELECT asn FROM asn_datacenters ORDER BY asn" \
    | awk 'NF {print "- " $0}'
} > "$OUT_DIR/asn_datacenters.yaml"
echo "wrote $OUT_DIR/asn_datacenters.yaml"

echo ""
echo "Done. Now: git diff $OUT_DIR/, commit, then run alembic upgrade head."
