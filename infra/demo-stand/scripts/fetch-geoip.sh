#!/usr/bin/env bash
# Fetch the GeoLite2 databases the A6 reputation stage needs (country + ASN)
# into infra/demo-stand/geoip/. These are license-gated by MaxMind and are NOT
# committed to the repo; run this once on the stand (and ~monthly to refresh).
#
# Requires a free MaxMind account license key:
#   https://www.maxmind.com/en/geolite2/signup  ->  Account ->  License keys
#
# Usage:
#   MAXMIND_LICENSE_KEY=xxxxxxxx ./scripts/fetch-geoip.sh
#
# After it runs, (re)start the stand; geoip.lua picks the files up at init.
set -euo pipefail

if [ -z "${MAXMIND_LICENSE_KEY:-}" ]; then
    echo "error: MAXMIND_LICENSE_KEY is not set." >&2
    echo "       Get a free key at https://www.maxmind.com/en/geolite2/signup" >&2
    exit 1
fi

# Resolve the geoip dir relative to this script (scripts/ -> ../geoip).
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dest_dir="${script_dir}/../geoip"
mkdir -p "${dest_dir}"

editions="GeoLite2-Country GeoLite2-ASN"
base_url="https://download.maxmind.com/app/geoip_download"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

for edition in ${editions}; do
    echo "Fetching ${edition} ..."
    tarball="${tmp_dir}/${edition}.tar.gz"
    curl -fsSL \
        "${base_url}?edition_id=${edition}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz" \
        -o "${tarball}"

    # The archive contains <edition>_<date>/<edition>.mmdb — extract just the
    # .mmdb to a flat, date-less path the Lua side expects.
    mmdb_path="$(tar -tzf "${tarball}" | grep "/${edition}.mmdb$" | head -n1)"
    if [ -z "${mmdb_path}" ]; then
        echo "error: ${edition}.mmdb not found inside the archive" >&2
        exit 1
    fi
    tar -xzf "${tarball}" -C "${tmp_dir}" "${mmdb_path}"
    mv -f "${tmp_dir}/${mmdb_path}" "${dest_dir}/${edition}.mmdb"
    echo "  -> ${dest_dir}/${edition}.mmdb"
done

echo "Done. Restart the stand to load the databases."
