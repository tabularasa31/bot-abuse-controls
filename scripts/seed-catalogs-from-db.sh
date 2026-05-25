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

# Квотируем ключи и значения как YAML single-quoted scalars: внутри
# одинарных кавычек YAML экранирует только саму ' через ''. Awk %q
# непортабелен (только gawk 4.2+) и экранирует под shell, не под YAML —
# поэтому делаем bash-ом. PR-59 review (gemini high / codex P1).
yaml_sq() {
  # echo single-quoted YAML scalar для строки $1.
  local s=${1//\'/\'\'}
  printf "'%s'" "$s"
}

# tls_fp_blocklist: map fp → status. Legacy DB-таблица из 0001_init.sql
# называется `fp_blocklist` (миграция 0004 её дропнет); выходной файл —
# `tls_fp_blocklist.yaml` (имя из vision/entities-reference.md, PR-62 rename).
# Скрипт идёт ДО 0004, поэтому SQL читает старое имя.
{
  echo "# tls_fp_blocklist.yaml — seeded from DB at $(date -u +%FT%TZ)."
  echo "# Формат: <fp>: <status>"
  psql_q "SELECT fp, status FROM fp_blocklist ORDER BY fp" \
    | while IFS=$'\t' read -r key status; do
        [[ -z "$key" ]] && continue
        printf "%s: %s\n" "$(yaml_sq "$key")" "$status"
      done
} > "$OUT_DIR/tls_fp_blocklist.yaml"
echo "wrote $OUT_DIR/tls_fp_blocklist.yaml"

# ua_blacklist: map pattern → status. Pattern содержит спецсимволы regex —
# YAML single-quoted скаляр доставляет их без интерпретации.
{
  echo "# ua_blacklist.yaml — seeded from DB at $(date -u +%FT%TZ)."
  echo "# Формат: <pattern>: <status>"
  psql_q "SELECT pattern, status FROM ua_blacklist ORDER BY pattern" \
    | while IFS=$'\t' read -r key status; do
        [[ -z "$key" ]] && continue
        printf "%s: %s\n" "$(yaml_sq "$key")" "$status"
      done
} > "$OUT_DIR/ua_blacklist.yaml"
echo "wrote $OUT_DIR/ua_blacklist.yaml"

# ip_blocklist: map cidr → status.
{
  echo "# ip_blocklist.yaml — seeded from DB at $(date -u +%FT%TZ)."
  echo "# Формат: <cidr>: <status>"
  psql_q "SELECT cidr, status FROM ip_blocklist ORDER BY cidr" \
    | while IFS=$'\t' read -r key status; do
        [[ -z "$key" ]] && continue
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
