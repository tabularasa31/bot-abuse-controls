#!/usr/bin/env bash
# seed-catalogs-from-db.sh — одноразовая миграция содержимого slow-каталогов
# из Postgres в файлы catalogs/*.yaml. Запускайте ДО `alembic upgrade head`
# (миграция 0004 дропает таблицы). После выполнения проверьте `git diff
# catalogs/`, закоммитьте seed и накатите миграцию.
#
# Использование:
#   POSTGRES_DSN="postgres://user:pass@host:5432/db" \
#     ./scripts/seed-catalogs-from-db.sh [out_dir]
#
# out_dir по умолчанию ./catalogs (относительно текущего pwd).
#
# Требует psql.
#
# Скрипт пишет YAML вручную (без зависимости от Go/yaml-генератора), чтобы
# не вводить новых артефактов сборки. Формат симметричен тому, что
# ожидает internal/filesource (см. docs/architecture-decisions/006).

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
  # -At: tuples-only, unaligned. -F'<TAB>': field separator. -X: не читать .psqlrc.
  PGOPTIONS="--client-min-messages=warning" \
    psql "$POSTGRES_DSN" -X -At -F$'\t' -c "$1"
}

# version: singleton.
VERSION=$(psql_q "SELECT version FROM catalog_version WHERE id = 1")
if [[ -n "$VERSION" ]]; then
  echo "$VERSION" > "$OUT_DIR/version"
  echo "wrote $OUT_DIR/version: $VERSION"
fi

# fp_blocklist: map fp → status.
{
  echo "# fp_blocklist.yaml — seeded from DB at $(date -u +%FT%TZ)."
  echo "# Формат: <fp>: <status>"
  psql_q "SELECT fp, status FROM fp_blocklist ORDER BY fp" \
    | awk -F'\t' 'NF==2 {printf "%q: %s\n", $1, $2}'
} > "$OUT_DIR/fp_blocklist.yaml"
echo "wrote $OUT_DIR/fp_blocklist.yaml"

# ua_blacklist: map pattern → status. Pattern может содержать спецсимволы YAML,
# поэтому квотируем через %q.
{
  echo "# ua_blacklist.yaml — seeded from DB at $(date -u +%FT%TZ)."
  echo "# Формат: <pattern>: <status>"
  psql_q "SELECT pattern, status FROM ua_blacklist ORDER BY pattern" \
    | awk -F'\t' 'NF==2 {printf "%q: %s\n", $1, $2}'
} > "$OUT_DIR/ua_blacklist.yaml"
echo "wrote $OUT_DIR/ua_blacklist.yaml"

# ip_blocklist: map cidr → status.
{
  echo "# ip_blocklist.yaml — seeded from DB at $(date -u +%FT%TZ)."
  echo "# Формат: <cidr>: <status>"
  psql_q "SELECT cidr, status FROM ip_blocklist ORDER BY cidr" \
    | awk -F'\t' 'NF==2 {printf "%q: %s\n", $1, $2}'
} > "$OUT_DIR/ip_blocklist.yaml"
echo "wrote $OUT_DIR/ip_blocklist.yaml"

# ip_whitelist: sequence of cidr.
{
  echo "# ip_whitelist.yaml — seeded from DB at $(date -u +%FT%TZ)."
  psql_q "SELECT cidr FROM ip_whitelist ORDER BY cidr" \
    | awk 'NF {printf "- %q\n", $0}'
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
