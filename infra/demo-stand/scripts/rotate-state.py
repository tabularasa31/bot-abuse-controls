#!/usr/bin/env python3
"""Bound the growth of analyze.py's lifetime state (D7).

seen-fps.json and ip-cache.json accumulate every fp / IP ever seen. On the demo
stand that is a few thousand records; on a production CDN operator edge (millions of
unique fp/IP per day) it would balloon into gigabytes and slow analyze.py down.

This script moves the aged-out tail into state/archive/YYYY-MM.json and drops
low-signal one-offs, keeping the active files small. analyze.py lazily restores
any archived key the moment it reappears in the logs, so nothing is lost — the
history just lives in a monthly shard until then.

Run it from cron BEFORE analyze.py (the backend run.sh already does).
The actual rotation logic lives in analyze.rotate_state() so analyze.py's lazy
restore and this producer share one definition of "old"; this file is the thin
CLI/cron wrapper.

Knobs (env vars, also documented in scripts/README.md):
    STATE_FP_TTL_DAYS=30        fp archived once last_seen < today - N days
    STATE_IP_TTL_DAYS=7         IP archived once last_seen < today - N days
                                (ASN/rDNS churns faster, so a shorter TTL)
    STATE_COMPACT_MIN_COUNT=3   count < N AND >7d idle -> dropped (stray probe)
    ABUSE_CONTROLS_ROOT=<path>  repo root holding state/ (default: repo checkout)

Usage:
    rotate-state.py            # rotate using the env-configured TTLs
    rotate-state.py --dry-run  # report what would move, change nothing
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# analyze.py is the single source of truth for the rotation logic and the state
# paths. It sits next to this file; sys.path[0] is this dir when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze as az  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Rotate analyze.py lifetime state.")
    ap.add_argument("--dry-run", action="store_true",
                    help="report counts without writing any files")
    ap.add_argument("--fp-ttl-days", type=int, default=az.STATE_FP_TTL_DAYS)
    ap.add_argument("--ip-ttl-days", type=int, default=az.STATE_IP_TTL_DAYS)
    ap.add_argument("--min-count", type=int, default=az.STATE_COMPACT_MIN_COUNT)
    args = ap.parse_args()

    if args.dry_run:
        # Count against an in-memory copy without touching disk: load, run the
        # same predicate, but don't save or archive.
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).astimezone().date()

        def preview(store, last_seen, ttl):
            archived = dropped = 0
            for entry in store.values():
                ls = az._parse_day(last_seen(entry) or "")
                if ls is None:
                    continue
                idle = (today - ls).days
                if (entry.get("count", 0) < args.min_count
                        and idle > az.STATE_COMPACT_MIN_IDLE_DAYS):
                    dropped += 1
                elif idle > ttl:
                    archived += 1
            return {"archived": archived, "dropped": dropped,
                    "kept": len(store) - archived - dropped}

        fp = preview(az.load_seen(), az._fp_last_seen, args.fp_ttl_days)
        ip = preview(az.load_ip_cache(), az._ip_last_seen, args.ip_ttl_days)
        summary = {"fps": fp, "ips": ip}
        prefix = "rotate-state [dry-run]"
    else:
        summary = az.rotate_state(fp_ttl=args.fp_ttl_days,
                                  ip_ttl=args.ip_ttl_days,
                                  min_count=args.min_count)
        prefix = "rotate-state"

    fp, ip = summary["fps"], summary["ips"]
    print(f"{prefix}: fps archived={fp['archived']} dropped={fp['dropped']} "
          f"kept={fp['kept']} | ips archived={ip['archived']} "
          f"dropped={ip['dropped']} kept={ip['kept']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
