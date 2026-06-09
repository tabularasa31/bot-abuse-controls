#!/usr/bin/env python3
"""
Daily traffic analyzer for the abuse-controls demo stand (resty).

Reads the Phase 1 structured `BAC_LOG {json}` lines the stand emits to
docker stdout (container nginx-demo), builds a per-fingerprint view, and
produces a blocklist-candidate report (markdown / HTML / subject line).
fp comes from the record's `tls_fp` field; cipher_count is derived from
the fp token. Lifetime state (seen-fps.json) is keyed by fp.

Lives in the repo and runs from the on-VM git checkout, so it
auto-updates with the stand (cron pulls main + reloads). State and
report archives live under the repo root's state/ and reports/ (both
gitignored).

Output modes:
    analyze.py            -> markdown (archived to reports/)
    analyze.py --html     -> HTML for email
    analyze.py --subject  -> single line for the email Subject:
"""

from __future__ import annotations
import argparse
import html
import json
import re
import subprocess
import sys
import urllib.request
import urllib.parse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Repo-root-relative state so the analyzer travels with the git checkout
# (cron pulls main + reloads). Default: repo root, three parents up from
# infra/demo-stand/scripts/analyze.py. Override with ABUSE_CONTROLS_ROOT.
import os
ROOT = Path(os.environ.get("ABUSE_CONTROLS_ROOT")
            or Path(__file__).resolve().parents[3])
STATE_DIR = ROOT / "state"
REPORTS_DIR = ROOT / "reports"
# Slow catalogs (ADR-006) — git source of truth. The promotion gates read
# ip_whitelist / tls_fp_browser_profiles / tls_fp_catalog from here, and the
# blocklist itself (tls_fp_blocklist.yaml) for the staleness/dedup views.
CATALOGS_DIR = Path(os.environ.get("CATALOGS_DIR") or (ROOT / "catalogs"))
SEEN_FPS = STATE_DIR / "seen-fps.json"
IP_CACHE = STATE_DIR / "ip-cache.json"
# When each fp first appeared in the catalog as staging — the true dwell clock
# for the staging→active gate (§D), independent of the Loki window span.
STAGING_SINCE_FILE = STATE_DIR / "staging-since.json"
# Pre-recreate log snapshots. update.sh dumps `docker logs` here before
# rebuilding the container (a recreate drops the container's docker-json log
# history). We fold these back in so a rebuild deploy leaves no gap.
ARCHIVE_DIR = STATE_DIR / "bac-archive"
# Aged-out lifetime records (rotate-state.py / D7). Monthly shards keyed by the
# record's last-seen month. Distinct from bac-archive above (which holds raw
# events, not lifetime state). seen-fps.json / ip-cache.json grow unbounded on a
# production edge (millions of unique fp/IP per day), so rotate-state.py moves
# the stale tail here and analyze.py lazily restores any key that reappears.
STATE_ARCHIVE_DIR = STATE_DIR / "archive"
# key -> shard-month index, so a restore lookup for a key that was never archived
# (the common case — brand-new fps appear every day) costs O(1) instead of
# parsing every monthly shard. Sibling of the archive dir so the shard glob
# (`archive/*.json`) never picks it up. Rebuilt from the shards if absent/corrupt.
STATE_ARCHIVE_INDEX = STATE_DIR / "archive-index.json"
# TTL / compaction knobs (env-overridable; set in the backend analytics run.sh).
# An fp/IP is ARCHIVED once its last_seen is older
# than its TTL; a low-signal record (count < min AND >7d idle, i.e. a likely
# one-off probe) is DROPPED outright (not archived — nothing worth restoring).
STATE_FP_TTL_DAYS = int(os.environ.get("STATE_FP_TTL_DAYS", "30"))
STATE_IP_TTL_DAYS = int(os.environ.get("STATE_IP_TTL_DAYS", "7"))
STATE_COMPACT_MIN_COUNT = int(os.environ.get("STATE_COMPACT_MIN_COUNT", "3"))
# A record must be idle this long before compaction can drop it, regardless of
# TTL — guards a brand-new low-count fp from being culled the same week.
STATE_COMPACT_MIN_IDLE_DAYS = 7
# Cold-storage retention: monthly shards older than this are deleted, so the
# archive itself stays bounded (hot/cold tiering, not infinite cold growth). The
# value of restoring a fp's history decays with age — detection is about recent
# behaviour — so a few months is plenty for the slow-burn anti-evasion case. 0
# disables pruning (keep forever).
STATE_ARCHIVE_RETENTION_MONTHS = int(os.environ.get("STATE_ARCHIVE_RETENTION_MONTHS", "6"))
_SHARD_MONTH_RE = re.compile(r"^\d{4}-\d{2}$")

# The stand's container. It emits one Phase 1 `BAC_LOG {json}` record per
# request to docker stdout.
CONTAINER = os.environ.get("BAC_CONTAINER", "nginx-demo")

# Event source. The analytics has moved off the edge onto the backend+obs VM,
# where Loki holds 7d of all edges' BAC_LOG centrally (docs/architecture/
# config-distribution.md, loki-config.yaml). `loki` is the default; `docker`
# (read the local nginx-demo container) stays for edge-side debugging.
#   - loki:  GET {LOKI_URL}/loki/api/v1/query_range {job="bac-edge"} over the
#            window. Promtail's `output` stage stores the bare BAC_LOG JSON as
#            the line body (no "BAC_LOG " prefix), so the fetch re-adds it for
#            _event_from_bac_line. Loki is in-network only (read API not exposed
#            externally) — run from inside the antibot-backend compose network.
#   - docker: `docker logs --since` on CONTAINER (original edge behaviour).
SOURCE = os.environ.get("BAC_SOURCE", "loki")
LOKI_URL = os.environ.get("LOKI_URL", "http://loki:3100")
# Default fetch window (hours). Overridden per-view in main() (the staging
# observation needs ≥ --min-staging-hours).
FETCH_HOURS_DEFAULT = int(os.environ.get("BAC_FETCH_HOURS", "25"))
# Loki query_range page size; we paginate forward past this.
LOKI_PAGE_LIMIT = int(os.environ.get("BAC_LOKI_PAGE_LIMIT", "5000"))

# Resty's init marker (nginx error_log) carries the loaded blocklist size;
# 0 == shadow. Captured opportunistically — defaults to 0 if outside the
# docker-logs window (the container is reloaded, not restarted, on update).
INIT_RE = re.compile(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*?\[demo\] tls_fp_blocklist loaded: (\d+)")

LOG_TS_TZ = timezone.utc
WINDOW_HOURS = 24
# Only read archives recent enough to overlap the report window (mirrors the
# docker-logs --since margin). Older snapshots are aged out by split_24h anyway.
ARCHIVE_MAX_AGE_HOURS = WINDOW_HOURS + 1

BROWSER_CIPHER_COUNTS = {15, 16, 20}
BOT_UA_FAMILIES = {"curl", "python", "go", "okhttp", "bot", "scanner"}
BROWSER_UA_FAMILIES = {"chrome", "firefox", "safari"}

# Promotion-gate thresholds (docs/blocklist-scoring.md). Env-overridable so the
# analytics container and the promote scripts share one source of truth; CLI
# flags in main() override these in turn.
MAX_HUMAN_SHARE = float(os.environ.get("BAC_MAX_HUMAN_SHARE", "0.05"))
MIN_EVENTS = int(os.environ.get("BAC_MIN_EVENTS", "20"))
# Days an fp must be observed before auto-promote to STAGING. 1 = promote on the
# first HIGH day: staging is observe-only (matches, doesn't block), so the real
# proving ground is the 48h staging→active window, not a pre-staging wait. The
# volume gate (MIN_EVENTS) still filters single-request blips.
MIN_DAYS_PROMOTE = int(os.environ.get("BAC_MIN_DAYS_PROMOTE", "1"))
# Inactivity threshold (days) after which a blocklist entry is an auto-demote
# candidate. > Loki's 7d retention, so the >7d tail leans on the seen-fps
# accumulator's last_seen, not the log window.
TTL_DAYS = int(os.environ.get("BAC_TTL_DAYS", "14"))
# staging→active observation gates (§D).
MIN_STAGING_HOURS = int(os.environ.get("BAC_MIN_STAGING_HOURS", "48"))
MIN_STAGING_MATCHES = int(os.environ.get("BAC_MIN_STAGING_MATCHES", "10"))
# D12 challenge solve-rate signal (docs/research/challenge-solve-rate-design.md).
# issued/solved are accumulated lifetime per-fp in seen-fps.json, counted only on
# `mode==active AND attack_mode==off` events. Start values are calibration-only
# (env-overridable, tuned later on real active-staging data — no code change).
MIN_CHALLENGE_ISSUED = int(os.environ.get("BAC_MIN_CHALLENGE_ISSUED", "10"))
LOW_SOLVE_RATE = float(os.environ.get("BAC_LOW_SOLVE_RATE", "0.05"))
HUMAN_SOLVE_RATE = float(os.environ.get("BAC_HUMAN_SOLVE_RATE", "0.5"))

KNOWN_TOOL_HASH_TAILS = {
    "2d5fbeed7632": "curl",
    "60bdc24aefcc": "python-requests",
    "1bb3b57910c1": "go-http-client",
    "3a034d2f4474": "claudebot",
    "10d89aa70559": "leakix-scanner",
    "fac63a6ff214": "unknown-impersonator-A",
    "277525798c1f": "okhttp",
}
KNOWN_TOOL_CIPHER_HASHES = {
    "de2bb2c70653": "curl",
    "bcf826a2cd28": "python-requests",
    "69e852b66fc7": "go-http-client",
    "cb588a7868d0": "claudebot",
    "6e5920975fda": "okhttp",
}

# URIs that legitimate visitors basically never request. Recon scanners
# hit these constantly. /robots.txt and /sitemap.xml are legitimate
# crawler endpoints — NOT in this list.
SUSPICIOUS_URI_RE = re.compile(
    r"(/admin|/wp-(admin|login)|/phpmyadmin|/pma\b|"
    r"/\.env|/\.git/|/\.aws/|/\.htaccess|/\.svn/|/\.DS_Store|"
    r"/etc/passwd|/proc/|/server-(status|info)|"
    r"/console\b|/manager/html|/jmx-console|/web-console|"
    r"/login\.action|/struts|/jenkins|/actuator|"
    r"/swagger|/graphql|/api/v\d|"
    r"/backup|/dump\b|/database|/db_dump|/sql_dump|"
    r"/cgi-bin|/shell|/eval|/cmd)",
    re.I,
)

def classify_ua(ua):
    if not ua or ua == "-":
        return "(empty)"
    if re.search(r"\b(ClaudeBot|GPTBot|PerplexityBot|YandexBot|Googlebot|bingbot|DuckDuckBot|Twitterbot|facebookexternalhit)\b", ua, re.I):
        return "bot"
    if re.search(r"(l9scan|nuclei|nikto|sqlmap|wpscan|masscan|zgrab|gobuster|ffuf|nmap)", ua, re.I):
        return "scanner"
    if re.search(r"\bchrom(e|ium)\b", ua, re.I):
        return "chrome"
    if re.search(r"\bfirefox\b", ua, re.I):
        return "firefox"
    if re.search(r"\bversion/.+safari\b", ua, re.I):
        return "safari"
    if re.search(r"curl/", ua, re.I):
        return "curl"
    if re.search(r"python", ua, re.I):
        return "python"
    if re.search(r"\bgo-http-client\b", ua, re.I):
        return "go"
    if re.search(r"\bokhttp\b", ua, re.I):
        return "okhttp"
    if re.search(r"(bot|crawler|spider|scrape)", ua, re.I):
        return "bot"
    return "other"


def parse_cipher_count(fp):
    try:
        return int(fp[4:6])
    except (ValueError, IndexError):
        return None


def parse_hashes(fp):
    parts = fp.split("_")
    if len(parts) >= 3:
        return parts[1], parts[2]
    return "", ""


def parse_ts(ts_str):
    return datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S").replace(tzinfo=LOG_TS_TZ)


DOCKER_LOGS_SINCE = os.environ.get("DOCKER_LOGS_SINCE", "25h")


def _parse_iso(ts):
    # "2026-05-20T15:54:18.780Z" -> aware UTC datetime
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _event_from_bac_line(line):
    """Parse one `BAC_LOG {json}` line into an event dict, or None if the line
    is not a usable BAC record (no marker, bad json, or no fingerprint).
    Shared by the docker-logs reader and the archive reader."""
    i = line.find("BAC_LOG ")
    if i < 0:
        return None
    try:
        rec = json.loads(line[i + len("BAC_LOG "):])
    except Exception:
        return None
    fp = rec.get("tls_fp")
    if not fp or fp == "-":
        return None  # no fingerprint — skip (bypass endpoints never emit BAC_LOG)
    status = rec.get("status")
    sm = rec.get("staging_match")
    d = {
        "fp": fp,
        "verdict": rec.get("verdict") or "pass",
        "rule": rec.get("rule") or "-",
        # D12 solve-rate signal filter (§A): valid only on active-host,
        # attack-off events. `mode` is the per-host enum (B11); `attack_mode`
        # is the edge boolean — None means the log predates the field rollout,
        # which _is_signal_event treats as not-countable (conservative).
        "mode": rec.get("mode") or "-",
        "attack_mode": rec.get("attack_mode"),
        "status": str(status) if status is not None else "-",
        "uri": rec.get("path") or "-",
        "remote": rec.get("ip") or "-",
        # geo/ASN the edge already resolved (A6, GeoLite2) and shipped in the
        # log. The analytics container is in-network for Loki and cannot reach a
        # public geo-IP API, so we use these instead of an external lookup.
        "asn": rec.get("asn"),
        "geo_country": rec.get("geo_country"),
        "ua": rec.get("ua") or "-",
        # A11 staged rollout: array of "<catalog>:<pattern_id>" the request
        # matched in staging (matched but not enforced). Drives the
        # staging→active observation (§D). Empty/absent when nothing matched.
        "staging_match": sm if isinstance(sm, list) else [],
    }
    ts_iso = rec.get("timestamp") or ""
    try:
        d["ts_dt"] = _parse_iso(ts_iso)
        d["ts"] = d["ts_dt"].strftime("%Y/%m/%d %H:%M:%S")
    except Exception:
        d["ts_dt"] = None
        d["ts"] = ts_iso
    d["cipher_count"] = parse_cipher_count(fp)
    cipher_hash, hash_tail = parse_hashes(fp)
    d["cipher_hash"] = cipher_hash
    d["hash_tail"] = hash_tail
    d["ua_family"] = classify_ua(d["ua"])
    return d


def _event_key(e):
    """Identity for dedup across log sources (docker logs vs archives)."""
    return (e["ts"], e["remote"], e["uri"], e["fp"])


def _fetch_one(container):
    """Pull recent BAC_LOG json records from the stand's docker log.

    `--since 25h` bounds the fetch as uptime grows. The resty init marker
    (`[demo] tls_fp_blocklist loaded: N`) gives the blocklist size; if it is
    outside the window (the container is reloaded, not restarted, on
    update) the size defaults to 0 and the report still works.

    Returns (events, blocklist_size, init_ts).
    """
    out = subprocess.run(
        ["docker", "logs", "--since", DOCKER_LOGS_SINCE, container],
        capture_output=True, text=True, check=False, timeout=30,
    )
    text = (out.stdout or "") + (out.stderr or "")
    blocklist_size = 0
    init_ts = None
    events = []
    for line in text.splitlines():
        m = INIT_RE.search(line)
        if m:
            blocklist_size = int(m.group(2))
            try:
                init_ts = parse_ts(m.group(1))
            except Exception:
                init_ts = None
            continue
        d = _event_from_bac_line(line)
        if d is not None:
            events.append(d)
    return events, blocklist_size, init_ts


def _read_archive_events(now_utc):
    """BAC_LOG events from pre-recreate snapshots in state/bac-archive/.

    A rebuild deploy recreates the container, so `docker logs` only sees the
    new instance; update.sh first dumps the old container's stream here. Only
    files recent enough to overlap the report window are read — events outside
    24h are dropped by split_24h regardless. Returns a (possibly empty) list."""
    if not ARCHIVE_DIR.is_dir():
        return []
    cutoff = (now_utc - timedelta(hours=ARCHIVE_MAX_AGE_HOURS)).timestamp()
    events = []
    for path in sorted(ARCHIVE_DIR.glob("*.log")):
        try:
            if path.stat().st_mtime < cutoff:
                continue
            with path.open("r", errors="replace") as fh:
                for line in fh:
                    d = _event_from_bac_line(line)
                    if d is not None:
                        events.append(d)
        except OSError:
            continue
    return events


def _fetch_loki(hours):
    """Pull BAC_LOG events from Loki over the last `hours`, paginating forward.

    Loki stores the bare JSON payload as the line body (promtail `output`
    stage), so we re-prefix `BAC_LOG ` before reusing _event_from_bac_line. Any
    connectivity/parse error degrades to an empty list (the report still
    renders, archives still fold). blocklist_size/init_ts are not derivable from
    Loki (it carries only BAC_LOG, not the resty init marker) → (events, 0, None);
    the report's mode line shows SHADOW under the Loki source."""
    base = LOKI_URL.rstrip("/") + "/loki/api/v1/query_range"
    now_ns = int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)
    step_start = now_ns - int(hours * 3600 * 1_000_000_000)
    events = []
    seen = set()  # (ts_str, line) — dedup across overlapping pages
    for _ in range(200):  # pagination safety cap
        qs = urllib.parse.urlencode({
            "query": '{job="bac-edge"}',
            "start": str(step_start), "end": str(now_ns),
            "limit": str(LOKI_PAGE_LIMIT), "direction": "forward",
        })
        req = urllib.request.Request(
            base + "?" + qs,
            headers={"User-Agent": "abuse-controls-analytics/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                payload = json.loads(resp.read())
        except Exception:
            break
        results = (payload.get("data") or {}).get("result") or []
        if not results:
            break
        n = 0
        stream_maxes = []
        for stream in results:
            smax = step_start
            for ts_str, line in stream.get("values", []):
                n += 1
                try:
                    ts_ns = int(ts_str)
                except (ValueError, TypeError):
                    ts_ns = step_start
                if ts_ns > smax:
                    smax = ts_ns
                key = (ts_str, line)
                if key in seen:
                    continue
                seen.add(key)
                d = _event_from_bac_line("BAC_LOG " + line)
                if d is not None:
                    events.append(d)
            stream_maxes.append(smax)
        if n < LOKI_PAGE_LIMIT:
            break
        # Page hit the limit → may be truncated. Advance to the MINIMUM of the
        # per-stream maxima so a stream cut earlier than others is not skipped;
        # the `seen` dedup drops the re-fetched overlap above that boundary.
        nxt = min(stream_maxes) if stream_maxes else step_start
        step_start = nxt if nxt > step_start else step_start + 1
    return events, 0, None


def fetch_events(source=None, hours=None):
    """Pull events from the configured source (Loki by default, or the edge
    container), merged with any pre-recreate archives so a rebuild deploy leaves
    no gap. A dead source yields an empty (archive-only) report, not an error.
    The 4th return value (per_source) is kept None so the renderers' optional
    comparison block stays inert — this stand has a single source."""
    source = source or SOURCE
    hours = hours or FETCH_HOURS_DEFAULT
    if source == "loki":
        events, blocklist_size, init_ts = _fetch_loki(hours)
    else:
        try:
            events, blocklist_size, init_ts = _fetch_one(CONTAINER)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            events, blocklist_size, init_ts = [], 0, None
    # Fold in archived pre-recreate events, deduped against the live stream
    # (sources are disjoint in time, but a dedup keeps repeated runs safe).
    archived = _read_archive_events(datetime.now(timezone.utc))
    if archived:
        seen_keys = {_event_key(e) for e in events}
        for e in archived:
            k = _event_key(e)
            if k not in seen_keys:
                seen_keys.add(k)
                events.append(e)
    return events, blocklist_size, init_ts, None


def load_seen():
    if not SEEN_FPS.exists():
        return {}
    try:
        return json.loads(SEEN_FPS.read_text())
    except Exception:
        return {}


def save_seen(seen):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    SEEN_FPS.write_text(json.dumps(seen, indent=2, sort_keys=True))


# Idempotency watermark: the ts of the newest event already folded into
# the lifetime counters. The docker-logs window (--since 25h) overlaps the
# 24h report window, and manual runs re-read it, so without this the
# lifetime counts in seen-fps.json / ip-cache.json double-count. Only
# events strictly newer than the watermark update the counters; the
# windowed report itself is recomputed each run and is unaffected.
LAST_COUNTED = STATE_DIR / "last-counted.txt"


def load_watermark():
    try:
        return _parse_iso(LAST_COUNTED.read_text().strip())
    except Exception:
        return None


def save_watermark(dt):
    if dt is None:
        return
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    LAST_COUNTED.write_text(dt.astimezone(timezone.utc)
                            .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z\n")


def load_ip_cache():
    if not IP_CACHE.exists():
        return {}
    try:
        return json.loads(IP_CACHE.read_text())
    except Exception:
        return {}


def save_ip_cache(cache):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    IP_CACHE.write_text(json.dumps(cache, indent=2, sort_keys=True))


def seed_ip_cache_from_log(events, cache):
    """Populate ip_cache from the asn/geo_country the EDGE already resolves and
    ships in BAC_LOG (A6, GeoLite2) — no external geo-IP API.

    Why: the analytics container sits in-network for Loki and cannot reach a
    public geo-IP service, so the old external lookup failed wholesale and every
    per-ASN row rendered "(нет данных)" — and the DC-ASN scoring signal silently
    went dark too. The edge already does the lookup; we just read it.

    `hosting` (the DC signal) = membership in the asn_datacenters catalog, the
    same source the edge's reputation:asn_dc tag uses. Any accumulated `count`
    on an existing good entry is preserved (the lifetime pass increments it);
    entries that were previously errors are reset (they were never counted).
    A prior `last_seen` (the rotation clock, D7) survives the rebuild too."""
    dc = _load_asn_datacenters()
    for e in events:
        ip = e.get("remote")
        asn = e.get("asn")
        if not ip or ip == "-" or not asn or asn == "-":
            continue
        asn = str(asn)
        prev = cache.get(ip)
        good_prev = isinstance(prev, dict) and "error" not in prev
        count = prev["count"] if (good_prev and "count" in prev) else 0
        entry = {
            "asn": asn,
            "country": e.get("geo_country") or "",
            "hosting": asn in dc,
            "count": count,
            "source": "log",
        }
        # Carry forward the rotation clock if it was set; only added when present
        # so first-seen entries keep the original (last_seen-free) shape until
        # the lifetime pass stamps them.
        if good_prev and prev.get("last_seen"):
            entry["last_seen"] = prev["last_seen"]
        cache[ip] = entry


# --- Lifetime-state rotation (D7) ------------------------------------------
# seen-fps.json / ip-cache.json accumulate every fp/IP ever seen. rotate-state.py
# (run from cron BEFORE analyze.py) calls rotate_state() to move the aged-out
# tail into state/archive/YYYY-MM.json and drop low-signal one-offs; analyze.py
# calls restore_from_archive() to pull a key back the moment it reappears.

def _fp_last_seen(entry):
    """Last day an fp was seen, 'YYYY-MM-DD' or None. days_seen is the canonical
    clock (docs/blocklist-scoring.md §last-seen); fall back to a stored last_seen
    or first_seen for legacy/edge cases."""
    days = [d for d in entry.get("days_seen", []) if d]
    if days:
        return max(days)
    for k in ("last_seen", "first_seen"):
        v = entry.get(k)
        if v:
            return v[:10]
    return None


def _ip_last_seen(entry):
    """Last day an IP was seen, 'YYYY-MM-DD' or None. IP entries have no day list,
    so this leans on the last_seen the lifetime pass stamps; None ⇒ never stamped
    (legacy/just-seeded) and rotation leaves it alone rather than guess it stale."""
    v = entry.get("last_seen")
    return v[:10] if v else None


def _shard_path(month):
    return STATE_ARCHIVE_DIR / f"{month}.json"


def _load_shard(path):
    if not path.exists():
        return {"fps": {}, "ips": {}}
    try:
        d = json.loads(path.read_text())
    except Exception:
        return {"fps": {}, "ips": {}}
    if not isinstance(d, dict):  # corrupted / [] / null -> start clean
        return {"fps": {}, "ips": {}}
    d.setdefault("fps", {})
    d.setdefault("ips", {})
    return d


def _save_shard(path, data):
    STATE_ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True))


def _save_archive_index(idx):
    STATE_ARCHIVE_INDEX.parent.mkdir(parents=True, exist_ok=True)
    STATE_ARCHIVE_INDEX.write_text(json.dumps(idx, indent=2, sort_keys=True))


def _rebuild_archive_index():
    """Scan every shard once to rebuild the key->month index. The only full-scan
    path — runs when the index is missing/corrupt (fresh deploy, or after manual
    archive surgery: delete archive-index.json and it is rebuilt on next run)."""
    idx = {"fps": {}, "ips": {}}
    if STATE_ARCHIVE_DIR.exists():
        for path in sorted(STATE_ARCHIVE_DIR.glob("*.json")):
            month = path.stem
            shard = _load_shard(path)
            for kind in ("fps", "ips"):
                for key in shard.get(kind, {}):
                    idx[kind][key] = month
    _save_archive_index(idx)
    return idx


def _load_archive_index():
    """{'fps': {key: 'YYYY-MM'}, 'ips': {...}} mapping each archived key to its
    shard. Lets restore skip keys that were never archived without touching a
    single shard. Rebuilt from the shards if absent/corrupt."""
    try:
        d = json.loads(STATE_ARCHIVE_INDEX.read_text())
        if isinstance(d, dict):
            d.setdefault("fps", {})
            d.setdefault("ips", {})
            return d
    except Exception:
        pass
    return _rebuild_archive_index()


def archive_records(kind, records):
    """Merge {key: entry} into the monthly shard(s) for each record's last-seen
    month and update the key->month index. `kind` is 'fps' or 'ips'. A record
    with no resolvable last_seen lands in an 'unknown' shard so it is still
    recoverable by lazy restore."""
    last_seen = _fp_last_seen if kind == "fps" else _ip_last_seen
    by_month = defaultdict(dict)
    for key, entry in records.items():
        ls = last_seen(entry)
        by_month[ls[:7] if ls else "unknown"][key] = entry
    idx = _load_archive_index()
    kidx = idx.setdefault(kind, {})
    for month, recs in by_month.items():
        path = _shard_path(month)
        shard = _load_shard(path)
        shard[kind].update(recs)
        _save_shard(path, shard)
        for key in recs:
            kidx[key] = month
    _save_archive_index(idx)


def restore_from_archive(kind, keys):
    """Pop archived `kind` entries matching `keys` out of their monthly shards and
    return {key: entry}. Removes them from the shard AND the index (a record is
    either active or archived, never both) so re-archival doesn't double counts.

    The index gates the work: keys that were never archived — the common case,
    since brand-new fps/IPs appear every run — intersect to empty and cost zero
    shard reads. Only shards actually holding a wanted key are opened."""
    wanted = set(keys)
    if not wanted or not STATE_ARCHIVE_DIR.exists():
        return {}
    idx = _load_archive_index()
    kidx = idx.get(kind, {})
    by_month = defaultdict(set)
    for key in wanted:
        month = kidx.get(key)
        if month is not None:
            by_month[month].add(key)
    if not by_month:
        return {}  # nothing the index knows about -> no shard I/O
    found, idx_dirty = {}, False
    for month, mkeys in by_month.items():
        shard = _load_shard(_shard_path(month))
        bucket = shard.get(kind, {})
        hit = mkeys & bucket.keys()
        for key in hit:
            found[key] = bucket.pop(key)
        # Drop index entries for the hits and for any stale pointer (index said a
        # key was in this shard but it wasn't — keep the two from drifting).
        for key in mkeys:
            kidx.pop(key, None)
            idx_dirty = True
        if hit:
            path = _shard_path(month)
            # Drained shards are unlinked, not left as empty {} files to pile up.
            if not shard.get("fps") and not shard.get("ips"):
                try:
                    path.unlink()
                except OSError:
                    pass
            else:
                _save_shard(path, shard)
    if idx_dirty:
        _save_archive_index(idx)
    return found


def _months_ago(today, n):
    """The 'YYYY-MM' that is `n` whole months before today's month."""
    total = today.year * 12 + (today.month - 1) - n
    return f"{total // 12:04d}-{total % 12 + 1:02d}"


def prune_archive(now_utc=None, retention_months=None):
    """Delete monthly shards older than the retention horizon and drop their keys
    from the index, so the cold archive stays bounded instead of growing forever.
    retention 0 (or negative) disables pruning. The undated 'unknown' shard is
    never aged out (it has no month to compare). Returns {shards, records}."""
    now_utc = now_utc or datetime.now(timezone.utc)
    retention = (STATE_ARCHIVE_RETENTION_MONTHS if retention_months is None
                 else retention_months)
    result = {"shards": 0, "records": 0}
    if retention <= 0 or not STATE_ARCHIVE_DIR.exists():
        return result
    cutoff = _months_ago(now_utc.astimezone().date(), retention)  # prune months < cutoff
    for path in sorted(STATE_ARCHIVE_DIR.glob("*.json")):
        month = path.stem
        if not _SHARD_MONTH_RE.match(month) or month >= cutoff:
            continue
        shard = _load_shard(path)
        n = len(shard.get("fps", {})) + len(shard.get("ips", {}))
        try:
            path.unlink()
        except OSError:
            continue
        result["shards"] += 1
        result["records"] += n
    if result["shards"]:
        # Drop index entries that pointed into the deleted shards. 'unknown' and
        # any future-dated month sort >= cutoff and are kept.
        idx = _load_archive_index()
        changed = False
        for kind in ("fps", "ips"):
            kept = {k: m for k, m in idx.get(kind, {}).items()
                    if not (_SHARD_MONTH_RE.match(m) and m < cutoff)}
            if len(kept) != len(idx.get(kind, {})):
                idx[kind] = kept
                changed = True
        if changed:
            _save_archive_index(idx)
    return result


def _rotation_decision(entry, last_seen_str, today, ttl, min_count):
    """Classify one record: 'archive' | 'drop' | 'keep'. The single source of
    truth for the rotation rule — both rotate_state() and rotate-state.py's
    --dry-run preview call this, so the preview can never drift from a real run."""
    ls = _parse_day(last_seen_str or "")
    if ls is None:
        return "keep"  # no clock yet -> keep (don't guess it stale)
    idle = (today - ls).days
    if entry.get("count", 0) < min_count and idle > STATE_COMPACT_MIN_IDLE_DAYS:
        return "drop"            # likely a stray one-off probe
    if idle > ttl:
        return "archive"
    return "keep"


def rotate_state(now_utc=None, fp_ttl=None, ip_ttl=None, min_count=None,
                 retention_months=None):
    """Bound seen-fps.json / ip-cache.json growth. For each store: ARCHIVE entries
    idle longer than their TTL, DROP low-signal ones (count < min AND idle > the
    compaction floor) outright. Then PRUNE the cold archive of shards older than
    the retention horizon so it stays bounded too. Idempotent — safe to run before
    every analyze pass. Returns {fps, ips, archive_pruned} summaries.

    Fps currently in the blocklist catalog are EXEMPT — never archived or dropped.
    The auto-demote view (find_stale_blocklist_entries) only consults active
    seen-fps.json; archiving a silent catalog fp would erase the very last_seen
    signal that demotes it, stranding it enforced forever. The catalog is small
    and bounded, so keeping these active costs nothing against the size goal."""
    now_utc = now_utc or datetime.now(timezone.utc)
    today = now_utc.astimezone().date()
    fp_ttl = STATE_FP_TTL_DAYS if fp_ttl is None else fp_ttl
    ip_ttl = STATE_IP_TTL_DAYS if ip_ttl is None else ip_ttl
    min_count = STATE_COMPACT_MIN_COUNT if min_count is None else min_count
    # The catalog drives the fp exemption. If it is UNREADABLE (missing mount,
    # wrong CATALOGS_DIR, permission/I-O error) reading it yields {} — which would
    # mean "no exemptions" and let a silent enforced fp be archived out of the
    # stale view. So gate fp rotation on the catalog being readable (one read,
    # reused for the exemption set so the check can't diverge); unreadable -> skip
    # fp archival entirely (IP rotation + prune are catalog-independent and still
    # run). Distinct from an EMPTY-but-present catalog, which is readable and
    # legitimately yields no exemptions, so it rotates normally.
    catalog_present, catalog_map = _read_blocklist_catalog()
    catalog_fps = set(catalog_map)

    def _rotate(store, kind, ttl, exempt=frozenset()):
        last_seen = _fp_last_seen if kind == "fps" else _ip_last_seen
        archive, drop = {}, []
        for key, entry in store.items():
            if key in exempt:
                continue
            action = _rotation_decision(entry, last_seen(entry), today, ttl, min_count)
            if action == "drop":
                drop.append(key)
            elif action == "archive":
                archive[key] = entry
        for key in archive:
            del store[key]
        for key in drop:
            del store[key]
        if archive:
            archive_records(kind, archive)
        return {"archived": len(archive), "dropped": len(drop), "kept": len(store)}

    seen = load_seen()
    if catalog_present:
        fp_summary = _rotate(seen, "fps", fp_ttl, exempt=catalog_fps)
        save_seen(seen)
    else:
        sys.stderr.write(
            f"rotate_state: blocklist catalog unreadable at "
            f"{CATALOGS_DIR / 'tls_fp_blocklist.yaml'} — skipping fp archival to "
            f"avoid stranding enforced fps; rotate again once the catalogs mount "
            f"is readable. IP rotation + archive prune still run.\n")
        fp_summary = {"archived": 0, "dropped": 0, "kept": len(seen),
                      "skipped": "no-catalog"}

    ip_cache = load_ip_cache()
    ip_summary = _rotate(ip_cache, "ips", ip_ttl)
    save_ip_cache(ip_cache)

    archive_pruned = prune_archive(now_utc, retention_months)
    return {"fps": fp_summary, "ips": ip_summary, "archive_pruned": archive_pruned}


def classify_event(ev):
    """Return list of suspicion tags for an event."""
    tags = []
    fam = ev["ua_family"]
    cc = ev["cipher_count"]
    tail = ev["hash_tail"]
    cipher_hash = ev["cipher_hash"]
    tool_by_tail = KNOWN_TOOL_HASH_TAILS.get(tail)
    tool_by_cipher = KNOWN_TOOL_CIPHER_HASHES.get(cipher_hash)
    if fam in BROWSER_UA_FAMILIES:
        if tool_by_tail:
            tags.append(f"impersonator:{tool_by_tail}-as-{fam}")
        elif tool_by_cipher:
            tags.append(f"impersonator:{tool_by_cipher}-as-{fam}")
        elif cc is not None and cc not in BROWSER_CIPHER_COUNTS:
            tags.append(f"suspicious:{fam}-UA-with-{cc}-ciphers")
    if fam in BOT_UA_FAMILIES:
        tags.append(f"automation:{fam}")
    return tags


def is_bot_like(ev, ip_cache):
    """Single yes/no: does this event look bot-like by ANY signal?"""
    if classify_event(ev):
        return True
    if ev["ua_family"] in BOT_UA_FAMILIES:
        return True
    info = ip_cache.get(ev["remote"], {})
    if info.get("hosting"):
        return True
    return False


def is_genuine_browser(ev):
    """True if the event looks like a REAL browser, not a tool masking as one.

    Within one fp the cipher_count and hashes are fixed (they are part of the
    fp token), so "genuine browser" turns on the per-event UA plus those fixed
    properties: a real browser family AND a browser-consistent cipher count AND
    a fp whose hashes are not in our tool dictionaries. This is deliberately
    conservative — it errs toward calling something human, because it gates the
    purity veto (we would rather not block than block a real browser)."""
    return (
        ev["ua_family"] in BROWSER_UA_FAMILIES
        and ev["cipher_count"] in BROWSER_CIPHER_COUNTS
        and ev["hash_tail"] not in KNOWN_TOOL_HASH_TAILS
        and ev["cipher_hash"] not in KNOWN_TOOL_CIPHER_HASHES
    )


def human_share(events_for_fp):
    """Fraction of a fp's events that look like a genuine browser. The purity
    veto blocks promotion when this exceeds --max-human-share."""
    if not events_for_fp:
        return 0.0
    genuine = sum(1 for e in events_for_fp if is_genuine_browser(e))
    return genuine / len(events_for_fp)


# ---------------------------------------------------------------------------
# Auxiliary catalogs for promotion gates (allowlist / verified / legit-browser)
# ---------------------------------------------------------------------------

def _load_asn_datacenters():
    """catalogs/asn_datacenters.yaml — flat sequence of bare uint32 ASN. Hand-
    parsed (no yaml dep): lines like `- 24940  # comment`. Returns a set of ASN
    strings (matching the string form geoip.lua logs, e.g. "24940")."""
    asns = set()
    path = CATALOGS_DIR / "asn_datacenters.yaml"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return asns
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("-"):
            continue
        s = s[1:].split("#", 1)[0].strip().strip('"').strip("'")
        if s:
            asns.add(s)
    return asns


def _load_ip_whitelist():
    """catalogs/ip_whitelist.yaml — flat sequence of CIDR strings. Hand-parsed
    (no yaml dep): lines like `- 198.51.100.5/32  # comment`. Returns a list of
    ipaddress networks; unparseable entries are skipped."""
    import ipaddress
    nets = []
    path = CATALOGS_DIR / "ip_whitelist.yaml"
    try:
        text = path.read_text()
    except OSError:
        return nets
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("-"):
            continue
        s = s[1:].strip()
        s = s.split("#", 1)[0].strip().strip('"').strip("'")
        if not s:
            continue
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            continue
    return nets


def _ip_in_whitelist(ip, nets):
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


# --- D12 challenge solve-rate signal -----------------------------------------
# docs/research/challenge-solve-rate-design.md. Splits the old binary
# _fp_has_identity_allow (any verdict==allow) into a HARD identity veto
# (ip_whitelist/cookie_valid/... — stays binary) plus a challenge_pass LADDER
# (a bet by volume, not a binary shield), so one solved challenge no longer
# shields a headless fp forever.

def _is_signal_event(e):
    """True if this event is valid for the solve-rate signal (§A): the challenge
    was a verdict ABOUT the fp, not a host posture. Requires mode==active (under
    shadow the page is not served → solved always 0) and attack_mode==off (under
    attack L5 forces challenge on everyone, real humans bail → falsely low rate).
    attack_mode is None on logs predating the edge field — not countable."""
    return e.get("mode") == "active" and e.get("attack_mode") is False


def _challenge_counts(events):
    """(issued, solved) over signal-valid events. solved is counted STRICTLY on
    rule==challenge_pass, never on any verdict==allow: the clearance cookie
    fastpaths later requests as rule==cookie_valid (also allow), and counting
    those would let one solve inflate the numerator (design §single-use)."""
    issued = sum(1 for e in events
                 if _is_signal_event(e) and e.get("verdict") == "challenge")
    solved = sum(1 for e in events
                 if _is_signal_event(e)
                 and e.get("verdict") == "allow" and e.get("rule") == "challenge_pass")
    return issued, solved


def solve_signal(issued, solved):
    """Pure summary of the solve-rate signal. solve_rate is capped at 1.0: on the
    first load a solved event can fall inside the retention window while its
    paired issued is just below it (solved>issued); accumulation self-corrects."""
    rate = min(solved / issued, 1.0) if issued > 0 else 0.0
    return {"issued": issued, "solved": solved, "solve_rate": rate,
            "enough": issued >= MIN_CHALLENGE_ISSUED}


def _challenge_pass_gate(issued, solved):
    """The §B2 ladder → 'veto' | 'gray' | 'clear'. issued/solved are lifetime
    counts (from seen-fps, for scoring/candidates) or counts among staging
    matches (for find_staging_observation).

    Asymmetry is deliberate: a human's solve VETOES even on small N (protect
    people), but LIFTING the veto needs enough issued; in between → neither
    block nor forgive, but observe.
      issued < MIN  → solved>0: veto (someone solved at low volume — don't risk
                      promoting); solved==0: clear (this signal doesn't veto —
                      the volume gate MIN_EVENTS usually filters such fps anyway).
      issued >= MIN → rate>=HUMAN: veto (real solving → humans/legit browsers);
                      rate<=LOW:  clear (a bot that doesn't solve → promote OK,
                                  even after a few stray solves — the fixed bug);
                      otherwise:  gray (unconvincing → no auto-promote, no hard
                                  veto → staging observation)."""
    # issued <= 0 guards a misconfigured MIN_CHALLENGE_ISSUED==0 (the
    # `issued < MIN` check would not catch issued==0 then → ZeroDivisionError).
    if issued <= 0 or issued < MIN_CHALLENGE_ISSUED:
        return "veto" if solved > 0 else "clear"
    rate = min(solved / issued, 1.0)
    if rate >= HUMAN_SOLVE_RATE:
        return "veto"
    if rate <= LOW_SOLVE_RATE:
        return "clear"
    return "gray"


def _fp_hard_identity_allow(events_for_fp):
    """List of (ip, rule) pairs for events where the cascade let this fp through
    on a HARD positive-identity rule — ip_whitelist, policy.ip_whitelist
    (reputation.lua), cookie_valid (verdict.lua), i.e. any verdict==allow EXCEPT
    challenge_pass. Non-empty list is truthy so callers testing truthiness work
    unchanged. challenge_pass is excluded here and handled by _challenge_pass_gate:
    a solved challenge is no longer a permanent shield (design §B2)."""
    return [
        (e.get("remote") or "?", e.get("rule") or "?")
        for e in events_for_fp
        if e.get("verdict") == "allow" and e.get("rule") != "challenge_pass"
    ]


def _parse_blocklist_text(text):
    """Parse the flat `"<fp>": <status>` map (no yaml dep). Comment/blank lines
    ignored. Pure — no I/O — so callers can read once and reuse the text."""
    out = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if ":" not in s:
            continue
        key, _, val = s.partition(":")
        fp = key.strip().strip('"').strip("'")
        status = val.split("#", 1)[0].strip().strip('"').strip("'")
        if fp and status:
            out[fp] = status
    return out


def _read_blocklist_catalog():
    """Return (readable, {fp: status}). `readable` is False ONLY when the catalog
    file cannot be read — missing, permission denied, I/O error — as opposed to a
    present-but-empty catalog (readable=True, {}). The fp-rotation exemption keys
    off `readable`: an unreadable catalog must NOT silently read as 'no fps to
    exempt', or a silent enforced fp would be archived out of the stale view."""
    try:
        text = (CATALOGS_DIR / "tls_fp_blocklist.yaml").read_text()
    except OSError:
        return False, {}
    return True, _parse_blocklist_text(text)


def _parse_blocklist_yaml():
    """catalogs/tls_fp_blocklist.yaml → {fp: status}; {} if unreadable."""
    return _read_blocklist_catalog()[1]


def _require_catalog():
    """Abort loudly if the blocklist catalog file is missing. Otherwise the
    promotion gates (dedup/allowlist) and the stale/staging views would silently
    degrade to pass-all / empty (a missing catalogs mount must NOT read as 'no
    bad fps', else the autopilot auto-promotes unvetoed)."""
    p = CATALOGS_DIR / "tls_fp_blocklist.yaml"
    if not p.exists():
        sys.stderr.write(
            f"analyze: blocklist catalog not found at {p} — refusing to emit gate "
            f"data that would silently pass-all. Check the catalogs mount / CATALOGS_DIR.\n")
        sys.exit(3)


def _reconcile_staging_since(now_utc):
    """Maintain state/staging-since.json: stamp when each fp first appears in the
    catalog as staging (≈ when it entered staging), and drop entries that are no
    longer staging. Returns {fp: datetime} for the dwell calculation. The stamp
    can lag entry by up to one analytics interval — close enough for a 48h gate,
    and far more correct than the Loki-window span it replaces."""
    staging = {fp for fp, st in _parse_blocklist_yaml().items() if st == "staging"}
    try:
        raw = json.loads(STAGING_SINCE_FILE.read_text())
    except Exception:
        raw = {}
    now_iso = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    if not staging and raw:
        # Degenerate read: catalog parsed to zero staging fps but we have prior
        # history. This is far more likely a transient empty/truncated catalog
        # than every staging entry vanishing at once — do NOT wipe the accrued
        # dwell stamps (wiping would reset every fp's clock on the next run).
        out = raw
    else:
        out = {fp: raw.get(fp, now_iso) for fp in staging}  # add new, drop departed
        if out != raw:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            STAGING_SINCE_FILE.write_text(json.dumps(out, indent=2, sort_keys=True))
    since_map = {}
    for fp, iso in out.items():
        try:
            since_map[fp] = _parse_iso(iso)
        except Exception:
            since_map[fp] = now_utc
    return since_map


def split_24h(events, now_utc):
    cutoff = now_utc - timedelta(hours=WINDOW_HOURS)
    return [e for e in events if e.get("ts_dt") and e["ts_dt"] >= cutoff]


# ============================================================================
# Stats
# ============================================================================

def collect_window_stats(events, ip_cache):
    if not events:
        return {"n_events": 0, "n_fps": 0, "n_ips": 0, "n_dc": 0, "dc_pct": 0,
                "n_bot": 0, "bot_pct": 0, "fps": Counter(), "fams": Counter(),
                "verdicts": Counter(), "asns": Counter(), "uris": Counter()}
    fps = Counter(e["fp"] for e in events)
    fams = Counter(e["ua_family"] for e in events)
    verdicts = Counter(e["verdict"] for e in events)
    uris = Counter(e["uri"] for e in events)
    asns = Counter()
    n_dc = 0
    n_bot = 0
    for e in events:
        info = ip_cache.get(e["remote"], {})
        if "error" in info or not info:
            asns[("(нет данных)", False, "")] += 1
        else:
            asns[(info.get("asn") or "(unknown)",
                  info.get("hosting", False),
                  info.get("country", ""))] += 1
            if info.get("hosting"):
                n_dc += 1
        if is_bot_like(e, ip_cache):
            n_bot += 1
    return {
        "n_events": len(events),
        "n_fps": len(fps),
        "n_ips": len({e["remote"] for e in events}),
        "n_dc": n_dc, "dc_pct": (n_dc * 100 // len(events)) if events else 0,
        "n_bot": n_bot, "bot_pct": (n_bot * 100 // len(events)) if events else 0,
        "fps": fps, "fams": fams, "verdicts": verdicts,
        "asns": asns, "uris": uris,
    }


def collect_lifetime_stats(seen_fps, ip_cache):
    n_fps = len(seen_fps)
    n_events = sum(v.get("count", 0) for v in seen_fps.values())
    real_ips = {ip: v for ip, v in ip_cache.items() if "error" not in v}
    n_ips = len(real_ips)
    n_dc = sum(1 for v in real_ips.values() if v.get("hosting"))
    dc_pct = (n_dc * 100 // n_ips) if n_ips else 0
    asns = Counter()
    for ip, info in real_ips.items():
        c = info.get("count", 1)
        asns[(info.get("asn") or "(unknown)",
              info.get("hosting", False),
              info.get("country", ""))] += c
    fp_counts = Counter({fp: v.get("count", 0) for fp, v in seen_fps.items()})
    return {
        "n_events": n_events, "n_fps": n_fps, "n_ips": n_ips,
        "n_dc": n_dc, "dc_pct": dc_pct,
        "fps": fp_counts, "asns": asns,
    }


# ============================================================================
# Blocklist candidate scoring
# ============================================================================

def score_fp_candidate(fp, events_for_fp, ip_cache, seen_entry):
    """Return (score, reasons[]) for one fp. Higher = stronger blocklist case."""
    score = 0
    reasons = []
    tags = set()
    for e in events_for_fp:
        for t in classify_event(e):
            tags.add(t)
    has_impersonator = any(t.startswith("impersonator:") for t in tags)
    has_suspicious = any(t.startswith("suspicious:") for t in tags)
    has_automation = any(t.startswith("automation:") for t in tags)

    if has_impersonator:
        score += 3
        reasons.append("impersonator-маскировка (UA браузер, fp автоматизатор) +3")
    if has_suspicious:
        score += 1
        reasons.append("suspicious cipher count vs UA +1")
    if has_automation:
        score += 1
        reasons.append("automation UA (curl/python/go/...) +1")

    ips = {e["remote"] for e in events_for_fp}
    dc_ips = [ip for ip in ips
              if ip_cache.get(ip, {}).get("hosting")]
    if dc_ips:
        score += 1
        reasons.append(f"DC ASN: {len(dc_ips)}/{len(ips)} IP +1")
    if len(ips) >= 2:
        score += 1
        reasons.append(f"multi-IP: {len(ips)} разных IP +1")

    # Persistence — from state file
    days_seen = (seen_entry or {}).get("days_seen", [])
    if len(set(days_seen)) >= 2:
        score += 1
        reasons.append(f"persistent: {len(set(days_seen))} разных дней +1")

    # Suspicious URIs
    suspicious_uris = {e["uri"] for e in events_for_fp if SUSPICIOUS_URI_RE.search(e["uri"])}
    if suspicious_uris:
        score += 1
        reasons.append(f"recon URI: {', '.join(sorted(suspicious_uris)[:3])} +1")

    # D12 challenge solve-rate (lifetime, from state). +2: between impersonator
    # (+3, dictionary-exact) and weak heuristics (+1) — a strong behavioural
    # signal, hard to fake. Only ranks; the gate decision is separate (§B1).
    sig = solve_signal((seen_entry or {}).get("challenge_issued", 0),
                       (seen_entry or {}).get("challenge_solved", 0))
    if sig["enough"] and sig["solve_rate"] <= LOW_SOLVE_RATE:
        score += 2
        reasons.append(f"challenge не решается (issued={sig['issued']}, "
                       f"solved={sig['solved']}) +2")

    return score, reasons, tags


def find_blocklist_candidates(events, ip_cache, seen):
    """Return three lists: high, medium, low confidence candidates.

    The `score`/`tier` only RANK candidates for the report. Whether a candidate
    is safe to (auto-)promote is a separate decision carried in `gates` and
    `auto_eligible` (docs/blocklist-scoring.md §B/§C): score never blocks on its
    own. Two distinct false-positive risks are handled separately —
      • purity gate (human_share) — "an unknown real browser misread as a bot";
      • intent rule (impersonator OR recon) — "a shared tool fp (honest curl)
        whose block would hit legitimate automation".
    """
    whitelist_nets = _load_ip_whitelist()
    in_catalog = _parse_blocklist_yaml()
    by_fp = defaultdict(list)
    for e in events:
        by_fp[e["fp"]].append(e)
    candidates = []
    for fp, evs in by_fp.items():
        score, reasons, tags = score_fp_candidate(fp, evs, ip_cache, seen.get(fp))
        if score == 0:
            continue
        ips = {e["remote"] for e in evs}
        sample = evs[0]
        days = sorted(set((seen.get(fp) or {}).get("days_seen", [])))
        n_lifetime = (seen.get(fp) or {}).get("count", len(evs))
        hs = human_share(evs)
        has_impersonator = any(t.startswith("impersonator:") for t in tags)
        has_recon = any(SUSPICIOUS_URI_RE.search(e["uri"]) for e in evs)
        # fp token is fixed per fp, so any event's hashes identify the tool.
        known_tool = (sample["hash_tail"] in KNOWN_TOOL_HASH_TAILS
                      or sample["cipher_hash"] in KNOWN_TOOL_CIPHER_HASHES)
        # A generic shared tool fp (curl-as-curl): blocking it punishes every
        # legitimate user of that tool. recon by one actor does NOT make the
        # shared fp safe to auto-block — that belongs in ua_blacklist/ip_blocklist.
        # Only impersonation (browser UA on a tool fp) or recon on a non-generic
        # fp counts as auto-promote intent.
        generic_honest_tool = known_tool and not has_impersonator
        intent = has_impersonator or (has_recon and not generic_honest_tool)

        # D12 challenge_pass ladder (§B2), on lifetime issued/solved from state.
        # "veto" kills the allowlist gate; "gray" passes the gate but blocks
        # auto-promote (→ staging observation); "clear" imposes no constraint.
        # Read the counters and the two hard-identity components once so the
        # gate, the output dict, and the operator message all agree.
        cl_issued = (seen.get(fp) or {}).get("challenge_issued", 0)
        cl_solved = (seen.get(fp) or {}).get("challenge_solved", 0)
        cp_gate = _challenge_pass_gate(cl_issued, cl_solved)
        wl_hit = any(_ip_in_whitelist(ip, whitelist_nets) for ip in ips)
        hard_id = _fp_hard_identity_allow(evs)

        gates = {
            "purity": hs <= MAX_HUMAN_SHARE,
            "volume": n_lifetime >= MIN_EVENTS and len(ips) >= 1,
            "allowlist": not wl_hit and not hard_id and cp_gate != "veto",
            "dedup": fp not in in_catalog,
        }
        if score >= 5:
            tier = "HIGH"
        elif score >= 3:
            tier = "MEDIUM"
        else:
            tier = "LOW"
        auto_eligible = (
            tier == "HIGH"
            and len(days) >= MIN_DAYS_PROMOTE
            and all(gates.values())
            and intent
            and cp_gate != "gray"   # gray solve-rate → staging observation, not auto-promote
        )

        # Operator-facing one-liner that explains the gate outcome, not just the
        # tier — so the report says WHY a HIGH was/ wasn't auto-promoted.
        if auto_eligible:
            suggested_action = "auto-promote eligible → PR (staging), наблюдение → active"
        elif tier == "HIGH" and not intent:
            suggested_action = ("HIGH без impersonator/recon: общий tool-fp, hard-block "
                                "заденет легит-автоматизацию → кейс для ua_blacklist/ip_blocklist, "
                                "решение за человеком")
        elif tier == "HIGH" and not gates["purity"]:
            suggested_action = (f"HIGH, но purity-вето: human_share {hs:.2f} > "
                                f"{MAX_HUMAN_SHARE} (под fp есть живые браузеры) — не блокировать")
        elif tier == "HIGH" and not gates["volume"]:
            suggested_action = (f"HIGH, но мало данных: lifetime {n_lifetime} < {MIN_EVENTS} "
                                f"или дней {len(days)} < {MIN_DAYS_PROMOTE} — наблюдать")
        elif tier == "HIGH" and (wl_hit or hard_id):
            if wl_hit:
                wl_ips = [ip for ip in ips if _ip_in_whitelist(ip, whitelist_nets)]
                ip_str = ", ".join(sorted(wl_ips)[:3]) + ("…" if len(wl_ips) > 3 else "")
                suggested_action = (
                    f"HIGH, жёсткое вето: IP в ip_whitelist ({ip_str}) — не блокировать"
                )
            else:
                rule_counts = Counter(rule for _, rule in hard_id)
                hit_ips = sorted({ip for ip, _ in hard_id})
                rules_str = ", ".join(
                    f"{r}×{c}" if c > 1 else r for r, c in rule_counts.most_common(3)
                )
                ip_str = ", ".join(hit_ips[:2]) + ("…" if len(hit_ips) > 2 else "")
                suggested_action = (
                    f"HIGH, жёсткое вето: identity-allow в логе "
                    f"(rule={rules_str}, IP={ip_str}, {len(hard_id)} событий) — "
                    f"не блокировать, проверить вручную"
                )
        elif tier == "HIGH" and cp_gate == "veto":
            suggested_action = (f"HIGH, но challenge решается (issued={cl_issued}, "
                                f"solved={cl_solved}) — под fp есть люди/легит, не блокировать")
        elif tier == "HIGH" and cp_gate == "gray":
            suggested_action = ("HIGH, но challenge solve-rate в серой зоне "
                                f"({LOW_SOLVE_RATE}–{HUMAN_SOLVE_RATE}) — не авто-промоут, "
                                "staging-наблюдение")
        elif tier == "HIGH" and not gates["dedup"]:
            suggested_action = "уже в blocklist-каталоге"
        elif tier == "MEDIUM":
            suggested_action = "watch-list, нужен 2-й день данных + intent"
        else:
            suggested_action = "слабые сигналы — не блокировать"

        candidates.append({
            "fp": fp, "score": score, "tier": tier,
            "reasons": reasons, "tags": sorted(tags),
            "ips": sorted(ips), "n_ips": len(ips), "n_events_24h": len(evs),
            "n_lifetime": n_lifetime,
            "days_seen": days,
            "uris": sorted({e["uri"] for e in evs}),
            "sample_ua": sample["ua"][:120],
            "human_share": round(hs, 4),
            "has_impersonator": has_impersonator,
            "has_recon": has_recon,
            "generic_honest_tool": generic_honest_tool,
            "intent": intent,
            "gates": gates,
            "challenge_issued": cl_issued,
            "challenge_solved": cl_solved,
            "challenge_gate": cp_gate,
            "auto_eligible": auto_eligible,
            "suggested_action": suggested_action,
        })
    candidates.sort(key=lambda c: -c["score"])
    high = [c for c in candidates if c["tier"] == "HIGH"]
    medium = [c for c in candidates if c["tier"] == "MEDIUM"]
    low = [c for c in candidates if c["tier"] == "LOW"]
    return high, medium, low


def find_asn_watch_candidates(events, ip_cache):
    """ASNs where every event is bot-like and >=2 events seen. Suggested
    action: ASN-level challenge / rate-limit, not hard block."""
    by_asn = defaultdict(list)
    for e in events:
        info = ip_cache.get(e["remote"], {})
        if "error" in info or not info:
            continue
        asn = info.get("asn") or "(unknown)"
        by_asn[asn].append((e, info))
    candidates = []
    for asn, evs_with_info in by_asn.items():
        evs = [e for e, _ in evs_with_info]
        info_sample = evs_with_info[0][1]
        if len(evs) < 2:
            continue
        if not all(is_bot_like(e, ip_cache) for e in evs):
            continue
        candidates.append({
            "asn": asn,
            "country": info_sample.get("country", ""),
            "hosting": info_sample.get("hosting", False),
            "n_events": len(evs),
            "n_ips": len({e["remote"] for e in evs}),
            "n_fps": len({e["fp"] for e in evs}),
        })
    candidates.sort(key=lambda c: -c["n_events"])
    return candidates


# ============================================================================
# Auto-demote (staleness) and staging→active observation views
# ============================================================================

def _parse_day(day_str):
    try:
        return datetime.strptime(day_str, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


def find_stale_blocklist_entries(seen, now_utc, ttl_days):
    """Blocklist entries that have gone silent > ttl_days → auto-demote
    candidates. "last seen" = max(days_seen) from the seen-fps accumulator
    (persists beyond Loki's 7d window). An entry with no observations in state
    is reported as a candidate too, flagged `unknown` so the autopilot can be
    cautious."""
    today = now_utc.astimezone().date()
    out = []
    for fp, status in sorted(_parse_blocklist_yaml().items()):
        entry = seen.get(fp) or {}
        days = [d for d in (_parse_day(x) for x in entry.get("days_seen", [])) if d]
        last_seen = max(days) if days else None
        if last_seen is None:
            # No observation history — we CANNOT confirm this entry is stale (it
            # may have been promoted moments ago, or state was reset). Mark it
            # unknown with stale=False so the autopilot never auto-demotes it;
            # it is surfaced for a human to look at, not acted on automatically.
            out.append({"fp": fp, "status": status, "last_seen": None,
                        "days_silent": None, "lifetime": entry.get("count", 0),
                        "unknown": True, "stale": False,
                        "reason": "нет наблюдений в state — нужен человек, не авто-демоут"})
            continue
        days_silent = (today - last_seen).days
        if days_silent > ttl_days:
            out.append({"fp": fp, "status": status,
                        "last_seen": last_seen.isoformat(),
                        "days_silent": days_silent, "lifetime": entry.get("count", 0),
                        "unknown": False, "stale": True,
                        "reason": f"молчит {days_silent}д > {ttl_days}д"})
    return out


def find_staging_observation(events, now_utc, min_staging_hours, since_map=None):
    """For each staging entry in the catalog, summarise what it actually matched
    (staging_match) over the fetched window and return the activation verdict
    (§D). Needs a window ≥ min_staging_hours — the caller fetches accordingly.

    `since_map` (fp → datetime the entry was first seen in staging) gives the TRUE
    staging dwell time. Without it observed_hours degrades to the span of matched
    events in the fetched window, which is NOT dwell — a fp matched near the start
    of the window could look "observed 48h" minutes after promotion, and a
    long-staged fp whose traffic is all recent would never reach the threshold.
    The caller (main) maintains the since_map in staging-since.json."""
    since_map = since_map or {}
    whitelist_nets = _load_ip_whitelist()
    catalog = _parse_blocklist_yaml()
    staging_fps = [fp for fp, st in catalog.items() if st == "staging"]
    # Index events by fp once (O(E)) so the per-fp solve-rate count below is a
    # dict lookup, not another full scan per staging fp (was O(S·E)).
    events_by_fp = defaultdict(list)
    for e in events:
        if e.get("fp"):
            events_by_fp[e["fp"]].append(e)
    out = []
    for fp in sorted(staging_fps):
        token = "tls_fp_blocklist:" + fp
        matched = [e for e in events if token in (e.get("staging_match") or [])]
        n = len(matched)
        hs = human_share(matched)
        # Hard identity (whitelist IP or non-challenge_pass allow) still means
        # "caught a real client". challenge_pass is judged by solve_rate among
        # the active matches instead (§B2) — this is where HUMAN_SOLVE_RATE gets
        # real meaning: many solved challenges → humans → fp_caught.
        hard_hit = any(_ip_in_whitelist(e["remote"], whitelist_nets) for e in matched) \
            or bool(_fp_hard_identity_allow(matched))
        # Count solves by fp, NOT among `matched`: a solved challenge is emitted
        # by the separate /__challenge/verify endpoint, which never runs the
        # tls_fp staging stage, so the solve event carries tls_fp (the join key,
        # set on the verify path) but NOT the staging_match token. Counting only
        # `matched` (token-keyed) would miss every solve → undercount s_solved →
        # a real browser fp with many solves could still reach `activate`.
        s_issued, s_solved = _challenge_counts(events_by_fp.get(fp, []))
        cp_gate = _challenge_pass_gate(s_issued, s_solved)
        if fp in since_map:
            observed_hours = round((now_utc - since_map[fp]).total_seconds() / 3600, 1)
        else:
            ts = [e["ts_dt"] for e in matched if e.get("ts_dt")]
            observed_hours = round((now_utc - min(ts)).total_seconds() / 3600, 1) if ts else 0.0

        if n == 0:
            verdict = "observe"  # silent — the stale path will pick it up
        elif hs > 0 or hard_hit or cp_gate == "veto":
            # real browser / hard-allowlisted client / fp actually solves challenges
            verdict = "fp_caught"
        elif cp_gate == "gray":
            verdict = "observe"  # unconvincing solve-rate — keep gathering data
        elif observed_hours >= min_staging_hours and n >= MIN_STAGING_MATCHES:
            verdict = "activate"
        else:
            verdict = "observe"
        out.append({
            "fp": fp, "n_matches": n, "human_share": round(hs, 4),
            "observed_hours": observed_hours, "allowlist_hit": hard_hit,
            "challenge_issued": s_issued, "challenge_solved": s_solved,
            "challenge_gate": cp_gate,
            "verdict": verdict,
        })
    return out


# ============================================================================
# Renderers
# ============================================================================

def enriched_label(info):
    if not info:
        return ""
    if "error" in info:
        return f"(lookup: {info['error']})"
    parts = []
    country = info.get("country") or ""
    asn = info.get("asn") or ""
    if asn:
        m = re.match(r"AS\d+\s+(.+)", asn)
        parts.append(m.group(1) if m else asn)
    if country:
        parts.append(country)
    if info.get("hosting"):
        parts.append("**DC**")
    return " · ".join(parts)


def _container_start_str(init_ts, source):
    """Human label for 'container last started'. Under the Loki source the resty
    init marker (`[demo] tls_fp_blocklist loaded: N`, nginx error_log) is NOT
    shipped to Loki, so init_ts is None BY DESIGN — say so rather than the
    alarming '(неизвестно)', which read like a failure (#3)."""
    if init_ts:
        return init_ts.astimezone().strftime("%Y-%m-%d %H:%M %Z")
    if source == "loki":
        return "n/a (Loki source: init-маркер не шипится в Loki)"
    return "(неизвестно)"


def render_markdown(events_24h, seen, blocklist_size, ip_cache, init_ts, now_utc, per_source=None, source=None):
    s24 = collect_window_stats(events_24h, ip_cache)
    sLT = collect_lifetime_stats(seen, ip_cache)
    high, medium, low = find_blocklist_candidates(events_24h, ip_cache, seen)
    asn_watch = find_asn_watch_candidates(events_24h, ip_cache)
    now_msk = now_utc.astimezone()
    init_str = _container_start_str(init_ts, source)

    L = []
    L.append(f"# Demo-stand report — {now_msk.strftime('%Y-%m-%d %H:%M %Z')}")
    L.append("")
    L.append("Стенд: https://bac.example.com (resty)")
    L.append(f"Режим: {'SHADOW (без блокировок)' if blocklist_size == 0 else f'ACTIVE — в blocklist {blocklist_size} fps'}")
    L.append(f"Контейнер последний раз стартовал: {init_str}")
    L.append("")
    L.append("")
    L.append("## Сводка")
    L.append("")
    L.append(f"**За 24 часа:** {s24['n_events']} запросов · **{s24['n_bot']} ({s24['bot_pct']}%) bot-like** · {s24['n_events'] - s24['n_bot']} ({100 - s24['bot_pct']}%) human-like · {s24['n_fps']} fp · {s24['n_ips']} IP · {s24['n_dc']} ({s24['dc_pct']}%) DC ASN")
    L.append("")
    L.append(f"**Lifetime:** {sLT['n_events']} запросов · {sLT['n_fps']} fp · {sLT['n_ips']} IP · {sLT['n_dc']} ({sLT['dc_pct']}%) DC ASN")
    L.append("")
    L.append(f"**Кандидаты на blocklist:** {len(high)} HIGH · {len(medium)} MEDIUM · {len(low)} LOW · {len(asn_watch)} ASN-watch")
    L.append("")
    L.append("---")
    L.append("")
    L.append("# Кандидаты на blocklist")
    L.append("")
    L.append("_Метод подсчёта: каждому fp начисляются очки по сигналам:_")
    L.append("- impersonator-маскировка: +3")
    L.append("- suspicious cipher count: +1")
    L.append("- automation UA: +1")
    L.append("- multi-IP (≥2): +1")
    L.append("- DC ASN: +1")
    L.append("- persistent (≥2 дня): +1")
    L.append("- recon URI (/admin /.env /wp-login etc): +1")
    L.append("")
    L.append("_Тиры: HIGH ≥5 баллов · MEDIUM 3-4 · LOW 1-2._")
    L.append("")
    for tier_name, tier_list in [("HIGH", high), ("MEDIUM", medium), ("LOW", low)]:
        if not tier_list:
            continue
        L.append(f"## {tier_name} confidence ({len(tier_list)} fp)")
        L.append("")
        for c in tier_list:
            L.append(f"### `{c['fp']}` — score {c['score']}")
            L.append("")
            L.append(f"- За сутки: **{c['n_events_24h']}** событий · lifetime: **{c['n_lifetime']}** · дней наблюдения: **{len(c['days_seen'])}**")
            L.append(f"- IP ({len(c['ips'])}): {', '.join(c['ips'][:5])}{'...' if len(c['ips']) > 5 else ''}")
            L.append(f"- Tags: {', '.join(c['tags']) or '(нет)'}")
            if c['uris']:
                L.append(f"- URI: {', '.join(f'`{u}`' for u in c['uris'][:5])}")
            L.append(f"- UA sample: `{c['sample_ua']}`")
            L.append(f"- Доказательная цепочка: {' / '.join(c['reasons'])}")
            L.append(f"- **Действие:** {c['suggested_action']}")
            L.append("")

    if asn_watch:
        L.append("## ASN-watch candidates")
        L.append("")
        L.append("_ASN, у которых **все** события bot-like + ≥2 события за сутки. Не hard-block — слишком много легитимного на типичных DC ASN (AWS, GCP). Кандидаты на ASN-level challenge или rate limit._")
        L.append("")
        L.append("| ASN | страна | DC? | events | IPs | fps |")
        L.append("|---|---|:---:|---:|---:|---:|")
        for c in asn_watch:
            L.append(f"| {c['asn']} | {c['country']} | {'DC' if c['hosting'] else ''} | {c['n_events']} | {c['n_ips']} | {c['n_fps']} |")
        L.append("")

    L.append("---")
    L.append("")
    L.append("# За последние 24 часа")
    L.append("")

    new_fps = sorted(set(e["fp"] for e in events_24h if e["fp"] not in seen))
    L.append(f"## Новые fingerprints ({len(new_fps)})")
    L.append("")
    if not new_fps:
        L.append("(нет)")
    else:
        L.append("| fp | первая UA | первый IP | ASN / гео | запросов |")
        L.append("|---|---|---|---|---:|")
        for fp in new_fps:
            sample = next(e for e in events_24h if e["fp"] == fp)
            count = sum(1 for e in events_24h if e["fp"] == fp)
            ua = sample["ua"][:55] + ("..." if len(sample["ua"]) > 55 else "")
            geo = enriched_label(ip_cache.get(sample["remote"], {}))
            L.append(f"| `{fp}` | `{ua}` | {sample['remote']} | {geo} | {count} |")

    L.append("")
    L.append("## Топ URIs (за сутки)")
    L.append("")
    L.append("| URI | запросов |")
    L.append("|---|---:|")
    for uri, c in s24["uris"].most_common(15):
        suspicious = " 🚨" if SUSPICIOUS_URI_RE.search(uri) else ""
        L.append(f"| `{uri}`{suspicious} | {c} |")

    L.append("")
    L.append("## Топ-10 fingerprints (за сутки)")
    L.append("")
    L.append("| fp | запросов | ciphers | пример UA |")
    L.append("|---|---:|---:|---|")
    for fp, c in s24["fps"].most_common(10):
        sample = next(e for e in events_24h if e["fp"] == fp)
        ua = sample["ua"][:50] + ("..." if len(sample["ua"]) > 50 else "")
        L.append(f"| `{fp}` | {c} | {sample['cipher_count']} | `{ua}` |")

    L.append("")
    L.append("## Per-ASN за сутки")
    L.append("")
    L.append("| ASN | страна | тип | запросов |")
    L.append("|---|---|---|---:|")
    for (asn, hosting, country), c in s24["asns"].most_common():
        L.append(f"| {asn} | {country} | {'datacenter' if hosting else 'other'} | {c} |")

    L.append("")
    L.append("## UA family + verdict (за сутки)")
    L.append("")
    L.append("| family | запросов |")
    L.append("|---|---:|")
    for fam, c in s24["fams"].most_common():
        L.append(f"| {fam} | {c} |")
    L.append("")
    L.append("| verdict | запросов |")
    L.append("|---|---:|")
    for v, c in s24["verdicts"].most_common():
        L.append(f"| {v} | {c} |")

    L.append("")
    L.append("---")
    L.append("")
    L.append("# Lifetime контекст (persistent state)")
    L.append("")
    L.append("## Топ-15 fingerprints lifetime")
    L.append("")
    L.append("| fp | total | дней | первый раз | первая UA |")
    L.append("|---|---:|---:|---|---|")
    for fp, c in sLT["fps"].most_common(15):
        info = seen.get(fp, {})
        ua = (info.get("first_ua") or "")[:45]
        first = info.get("first_seen", "?")
        days = len(set(info.get("days_seen", [])))
        L.append(f"| `{fp}` | {c} | {days} | {first} | `{ua}` |")

    L.append("")
    L.append("## Per-ASN lifetime")
    L.append("")
    L.append("| ASN | страна | тип | запросов |")
    L.append("|---|---|---|---:|")
    for (asn, hosting, country), c in sLT["asns"].most_common():
        L.append(f"| {asn} | {country} | {'datacenter' if hosting else 'other'} | {c} |")

    L.append("")
    L.append("---")
    L.append(f"State: {sLT['n_fps']} fp, {len(ip_cache)} IP в кеше enrichment.")
    return "\n".join(L) + "\n"


# ============================================================================
# HTML
# ============================================================================

CSS = """
body { font-family: -apple-system, system-ui, "Segoe UI", Helvetica, Arial, sans-serif;
       color: #222; max-width: 1000px; margin: 1em auto; padding: 0 1em; line-height: 1.5; }
h1 { margin: 0 0 0.2em; font-size: 22px; }
h2 { margin-top: 1.8em; margin-bottom: 0.4em; font-size: 17px;
     border-bottom: 1px solid #e1e4e8; padding-bottom: 4px; }
h3 { margin-top: 1.2em; margin-bottom: 0.4em; font-size: 14px; font-weight: 600; }
.headline { color: #586069; font-size: 14px; margin-bottom: 1.5em; }
.summary { background: #f6f8fa; border-radius: 4px; padding: 10px 14px;
           font-size: 13px; line-height: 1.7; }
.summary .label { color: #586069; }
.summary .val { color: #24292e; font-weight: 600; }
.summary .bot { color: #b71c1c; font-weight: 700; }
.summary .human { color: #2e7d32; font-weight: 600; }
.explain { color: #586069; font-size: 12.5px; font-style: italic; margin: 0 0 8px; }
.section-divider { margin: 2.5em 0 1em; padding: 8px 14px; background: #f1f5f9;
                   border-left: 4px solid #1f6feb; font-size: 14px; font-weight: 600; color: #1f6feb; }
.section-divider.candidates { border-color: #c62828; color: #c62828; background: #ffebee; }
.section-divider.lifetime { border-color: #6f42c1; color: #6f42c1; }
.candidate { background: #fafbfc; border: 1px solid #e1e4e8; border-left: 4px solid #c62828;
             padding: 10px 14px; margin: 8px 0; border-radius: 4px; font-size: 13px; }
.candidate.medium { border-left-color: #e65100; }
.candidate.low { border-left-color: #827717; }
.candidate .fp { font-size: 13px; font-weight: 600; }
.candidate .score { background: #c62828; color: white; padding: 2px 8px; border-radius: 12px;
                    font-size: 11px; font-weight: 700; margin-left: 6px; }
.candidate.medium .score { background: #e65100; }
.candidate.low .score { background: #827717; }
.candidate .action { background: #fff8e1; border: 1px solid #ffe082; padding: 4px 8px;
                     border-radius: 3px; margin-top: 6px; font-size: 12px; }
.candidate ul { margin: 4px 0 0; padding-left: 18px; font-size: 12px; }
table { border-collapse: collapse; width: 100%; margin: 6px 0 12px; font-size: 12px; }
th { text-align: left; background: #f6f8fa; padding: 6px 10px;
     border-bottom: 1px solid #d1d5da; font-weight: 600; }
td { padding: 5px 10px; border-bottom: 1px solid #eaecef; vertical-align: top; }
tr:nth-child(even) td { background: #fafbfc; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
code, .fp { font-family: "SF Mono", "Menlo", "Consolas", monospace; font-size: 11.5px; }
.tag-impersonator { background: #ffebee; color: #b71c1c; padding: 1px 6px;
                    border-radius: 3px; font-weight: 600; }
.tag-suspicious { background: #fff3e0; color: #e65100; padding: 1px 6px;
                  border-radius: 3px; font-weight: 600; }
.tag-automation { background: #fffde7; color: #827717; padding: 1px 6px;
                  border-radius: 3px; }
.dc-flag { background: #ede7f6; color: #4527a0; padding: 1px 5px;
           border-radius: 3px; font-size: 10.5px; font-weight: 600; margin-left: 4px; }
.uri-suspicious { background: #ffebee; color: #b71c1c; padding: 1px 4px; border-radius: 2px; }
.geo { color: #586069; font-size: 11.5px; }
.empty { color: #6a737d; font-style: italic; }
.mode-shadow { color: #2e7d32; font-weight: 600; }
.mode-active { color: #c62828; font-weight: 600; }
.legend { background: #fffbf0; border: 1px solid #f1e5b5; border-radius: 4px;
          padding: 8px 12px; margin: 6px 0 12px; font-size: 12px; }
hr { border: 0; border-top: 1px solid #e1e4e8; margin: 1.5em 0 1em; }
.footer { color: #6a737d; font-size: 12px; }
"""


def h(s):
    return html.escape(str(s) if s is not None else "")


def truncate(s, n):
    s = s or ""
    return s if len(s) <= n else s[: n - 1] + "…"


def html_enriched_cell(info):
    if not info:
        return ""
    if "error" in info:
        return f"<span class='geo'>(lookup: {h(info['error'])})</span>"
    parts = []
    country = info.get("country") or ""
    asn = info.get("asn") or ""
    rdns = info.get("rdns") or ""
    if asn:
        m = re.match(r"AS\d+\s+(.+)", asn)
        parts.append(h(m.group(1) if m else asn))
    if country:
        parts.append(f"<span class='geo'>{h(country)}</span>")
    body = " · ".join(parts)
    if info.get("hosting"):
        body += " <span class='dc-flag'>DC</span>"
    if rdns:
        body += f"<br><span class='geo'>{h(truncate(rdns, 50))}</span>"
    return body


def html_candidate(c, tier_cls):
    parts = [f"<div class='candidate {tier_cls}'>"]
    parts.append(f"<div><span class='fp'>{h(c['fp'])}</span> <span class='score'>score {c['score']}</span></div>")
    parts.append("<ul>")
    parts.append(f"<li>За сутки: <strong>{c['n_events_24h']}</strong> событий · lifetime: <strong>{c['n_lifetime']}</strong> · дней наблюдения: <strong>{len(c['days_seen'])}</strong></li>")
    ips_short = ', '.join(c['ips'][:5]) + ('...' if len(c['ips']) > 5 else '')
    parts.append(f"<li>IP ({len(c['ips'])}): {h(ips_short)}</li>")
    if c['tags']:
        tag_html = " ".join(f"<span class='tag-{t.split(':')[0]}'>{h(t)}</span>" for t in c['tags'])
        parts.append(f"<li>Tags: {tag_html}</li>")
    if c['uris']:
        uri_html = ", ".join(f"<code>{h(u)}</code>" for u in c['uris'][:5])
        parts.append(f"<li>URI: {uri_html}</li>")
    parts.append(f"<li>UA sample: <code>{h(c['sample_ua'])}</code></li>")
    parts.append(f"<li>Цепочка доказательств: {h(' / '.join(c['reasons']))}</li>")
    parts.append("</ul>")
    parts.append(f"<div class='action'><strong>Действие:</strong> {h(c['suggested_action'])}</div>")
    parts.append("</div>")
    return "".join(parts)


def render_html(events_24h, seen, blocklist_size, ip_cache, init_ts, now_utc, source=None):
    s24 = collect_window_stats(events_24h, ip_cache)
    sLT = collect_lifetime_stats(seen, ip_cache)
    high, medium, low = find_blocklist_candidates(events_24h, ip_cache, seen)
    asn_watch = find_asn_watch_candidates(events_24h, ip_cache)
    now_msk = now_utc.astimezone()
    init_str = _container_start_str(init_ts, source)

    parts = ["<!doctype html><html><head><meta charset='utf-8'>",
             f"<style>{CSS}</style></head><body>"]
    parts.append("<h1>Demo-stand traffic report</h1>")
    parts.append(
        f"<div class='headline'>{h(now_msk.strftime('%Y-%m-%d %H:%M %Z'))} · "
        f"<a href='https://bac.example.com'>bac.example.com</a> · "
        f"контейнер последний раз стартовал {h(init_str)}</div>"
    )

    mode_html = (
        "<span class='mode-shadow'>SHADOW</span>"
        if blocklist_size == 0
        else f"<span class='mode-active'>ACTIVE</span> ({blocklist_size} fps в blocklist)"
    )

    n_human = s24['n_events'] - s24['n_bot']
    human_pct = 100 - s24['bot_pct']
    parts.append(
        f"<div class='summary'>"
        f"<span class='label'>Режим:</span> {mode_html}<br>"
        f"<span class='label'>За 24 часа:</span> "
        f"<span class='val'>{s24['n_events']}</span> запросов · "
        f"<span class='bot'>{s24['n_bot']} ({s24['bot_pct']}%) bot-like</span> · "
        f"<span class='human'>{n_human} ({human_pct}%) human-like</span> · "
        f"<span class='val'>{s24['n_fps']}</span> fp · "
        f"<span class='val'>{s24['n_ips']}</span> IP · "
        f"<span class='val'>{s24['n_dc']}</span> ({s24['dc_pct']}%) DC ASN<br>"
        f"<span class='label'>Lifetime:</span> "
        f"<span class='val'>{sLT['n_events']}</span> запросов · "
        f"<span class='val'>{sLT['n_fps']}</span> fp · "
        f"<span class='val'>{sLT['n_ips']}</span> IP · "
        f"<span class='val'>{sLT['n_dc']}</span> ({sLT['dc_pct']}%) DC ASN<br>"
        f"<span class='label'>Кандидаты на blocklist:</span> "
        f"<span class='val' style='color:#c62828'>{len(high)}</span> HIGH · "
        f"<span class='val' style='color:#e65100'>{len(medium)}</span> MEDIUM · "
        f"<span class='val' style='color:#827717'>{len(low)}</span> LOW · "
        f"<span class='val'>{len(asn_watch)}</span> ASN-watch"
        f"</div>"
    )

    # Blocklist candidates section — show FIRST, before raw data
    parts.append("<div class='section-divider candidates'>Кандидаты на blocklist</div>")
    parts.append(
        "<div class='legend'>"
        "<strong>Скоринг:</strong> impersonator +3 · suspicious cipher +1 · automation UA +1 · "
        "multi-IP ≥2 +1 · DC ASN +1 · persistent ≥2 дней +1 · recon URI +1.<br>"
        "<strong>Тиры:</strong> <span style='color:#c62828; font-weight:700'>HIGH ≥5</span> · "
        "<span style='color:#e65100; font-weight:700'>MEDIUM 3-4</span> · "
        "<span style='color:#827717; font-weight:700'>LOW 1-2</span>."
        "</div>"
    )

    for tier_name, tier_list, tier_cls in [
        ("HIGH", high, "high"),
        ("MEDIUM", medium, "medium"),
        ("LOW", low, "low"),
    ]:
        if not tier_list:
            continue
        parts.append(f"<h2>{tier_name} confidence ({len(tier_list)} fp)</h2>")
        for c in tier_list:
            parts.append(html_candidate(c, tier_cls))

    if not (high or medium or low):
        parts.append("<p class='empty'>(нет кандидатов за сутки — нет fp с подозрительными сигналами)</p>")

    if asn_watch:
        parts.append("<h2>ASN-watch candidates</h2>")
        parts.append("<div class='explain'>ASN где <strong>все</strong> события bot-like + ≥2 события за сутки. Не hard-block — кандидаты на ASN-level challenge / rate limit.</div>")
        parts.append("<table><tr><th>ASN</th><th>страна</th><th>DC?</th><th>events</th><th>IPs</th><th>fps</th></tr>")
        for c in asn_watch:
            dc_tag = " <span class='dc-flag'>DC</span>" if c['hosting'] else ""
            parts.append(
                f"<tr><td>{h(c['asn'])}</td>"
                f"<td>{h(c['country'])}</td>"
                f"<td>{'DC' if c['hosting'] else ''}{dc_tag}</td>"
                f"<td class='num'>{c['n_events']}</td>"
                f"<td class='num'>{c['n_ips']}</td>"
                f"<td class='num'>{c['n_fps']}</td></tr>"
            )
        parts.append("</table>")

    parts.append("<div class='section-divider'>За последние 24 часа (сырые данные)</div>")

    new_fps = sorted(set(e["fp"] for e in events_24h if e["fp"] not in seen))
    parts.append(f"<h2>Новые fingerprints ({len(new_fps)})</h2>")
    if not new_fps:
        parts.append("<p class='empty'>(нет)</p>")
    else:
        parts.append("<table><tr><th>fp</th><th>первая UA</th><th>первый IP / ASN</th><th>запросов</th></tr>")
        for fp in new_fps:
            sample = next(e for e in events_24h if e["fp"] == fp)
            count = sum(1 for e in events_24h if e["fp"] == fp)
            info = ip_cache.get(sample["remote"], {})
            parts.append(
                f"<tr><td><span class='fp'>{h(fp)}</span></td>"
                f"<td>{h(truncate(sample['ua'], 65))}</td>"
                f"<td>{h(sample['remote'])}<br>{html_enriched_cell(info)}</td>"
                f"<td class='num'>{count}</td></tr>"
            )
        parts.append("</table>")

    parts.append("<h2>Топ URIs (за сутки)</h2>")
    parts.append("<div class='explain'>Красным выделены URI похожие на recon-сканирование (/admin, /.env, /wp-login, /.git, etc).</div>")
    parts.append("<table><tr><th>URI</th><th>запросов</th></tr>")
    for uri, c in s24["uris"].most_common(15):
        uri_html = f"<span class='uri-suspicious'><code>{h(uri)}</code></span>" if SUSPICIOUS_URI_RE.search(uri) else f"<code>{h(uri)}</code>"
        parts.append(f"<tr><td>{uri_html}</td><td class='num'>{c}</td></tr>")
    parts.append("</table>")

    parts.append("<h2>Топ-10 fingerprints за сутки</h2>")
    parts.append("<table><tr><th>fp</th><th>запросов</th><th>ciphers</th><th>пример UA</th></tr>")
    for fp, c in s24["fps"].most_common(10):
        sample = next(e for e in events_24h if e["fp"] == fp)
        parts.append(
            f"<tr><td><span class='fp'>{h(fp)}</span></td>"
            f"<td class='num'>{c}</td>"
            f"<td class='num'>{sample['cipher_count']}</td>"
            f"<td>{h(truncate(sample['ua'], 60))}</td></tr>"
        )
    parts.append("</table>")

    parts.append("<h2>Per-ASN за сутки</h2>")
    parts.append("<table><tr><th>ASN</th><th>страна</th><th>тип</th><th>запросов</th></tr>")
    for (asn, hosting, country), c in s24["asns"].most_common():
        dc_tag = " <span class='dc-flag'>DC</span>" if hosting else ""
        parts.append(
            f"<tr><td>{h(asn)}</td>"
            f"<td>{h(country)}</td>"
            f"<td>{'datacenter' if hosting else 'other'}{dc_tag}</td>"
            f"<td class='num'>{c}</td></tr>"
        )
    parts.append("</table>")

    parts.append("<h2>UA family + verdict (за сутки)</h2>")
    parts.append("<table style='width:auto; display:inline-block; margin-right:2em; vertical-align:top'>"
                 "<tr><th>UA family</th><th>запросов</th></tr>")
    for fam, c in s24["fams"].most_common():
        parts.append(f"<tr><td>{h(fam)}</td><td class='num'>{c}</td></tr>")
    parts.append("</table>")
    parts.append("<table style='width:auto; display:inline-block; vertical-align:top'>"
                 "<tr><th>verdict</th><th>запросов</th></tr>")
    for v, c in s24["verdicts"].most_common():
        parts.append(f"<tr><td>{h(v)}</td><td class='num'>{c}</td></tr>")
    parts.append("</table>")

    parts.append("<div class='section-divider lifetime'>Lifetime контекст</div>")
    parts.append("<h2>Топ-15 fingerprints lifetime</h2>")
    parts.append("<table><tr><th>fp</th><th>total</th><th>дней</th><th>первый раз</th><th>первая UA</th></tr>")
    for fp, c in sLT["fps"].most_common(15):
        info = seen.get(fp, {})
        days = len(set(info.get("days_seen", [])))
        parts.append(
            f"<tr><td><span class='fp'>{h(fp)}</span></td>"
            f"<td class='num'>{c}</td>"
            f"<td class='num'>{days}</td>"
            f"<td>{h(info.get('first_seen', '?'))}</td>"
            f"<td>{h(truncate(info.get('first_ua', ''), 50))}</td></tr>"
        )
    parts.append("</table>")

    parts.append("<h2>Per-ASN lifetime</h2>")
    parts.append("<table><tr><th>ASN</th><th>страна</th><th>тип</th><th>запросов</th></tr>")
    for (asn, hosting, country), c in sLT["asns"].most_common():
        dc_tag = " <span class='dc-flag'>DC</span>" if hosting else ""
        parts.append(
            f"<tr><td>{h(asn)}</td>"
            f"<td>{h(country)}</td>"
            f"<td>{'datacenter' if hosting else 'other'}{dc_tag}</td>"
            f"<td class='num'>{c}</td></tr>"
        )
    parts.append("</table>")

    parts.append("<hr>")
    parts.append(f"<div class='footer'>State: <strong>{sLT['n_fps']}</strong> fp, <strong>{len(ip_cache)}</strong> IP в кеше.</div>")
    parts.append("</body></html>")
    return "".join(parts)


def render_subject(events_24h, seen, sLT, ip_cache, now_utc):
    s24 = collect_window_stats(events_24h, ip_cache)
    high, medium, low = find_blocklist_candidates(events_24h, ip_cache, seen)
    date = now_utc.astimezone().strftime("%Y-%m-%d")
    return (f"[abuse-controls] {date} — 24ч: {s24['n_events']} events "
            f"({s24['n_bot']} bot {s24['bot_pct']}%) · кандидаты: "
            f"{len(high)}H {len(medium)}M {len(low)}L · "
            f"lifetime {sLT['n_events']}/{sLT['n_fps']}")


def main() -> int:
    global MAX_HUMAN_SHARE, MIN_EVENTS, MIN_DAYS_PROMOTE, MIN_STAGING_MATCHES
    global MIN_CHALLENGE_ISSUED, LOW_SOLVE_RATE, HUMAN_SOLVE_RATE
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--html", action="store_true")
    g.add_argument("--subject", action="store_true")
    # Machine-readable views consumed by the promotion tooling (read-only: they
    # never enrich-and-save or advance the watermark).
    g.add_argument("--candidates-json", action="store_true",
                   help="blocklist candidates + gates + auto_eligible as JSON")
    g.add_argument("--stale-blocklist-json", action="store_true",
                   help="catalog entries silent > --ttl-days as JSON (auto-demote)")
    g.add_argument("--staging-observation-json", action="store_true",
                   help="per staging-fp match summary + activate verdict as JSON")
    # Gate thresholds (override env/defaults; docs/blocklist-scoring.md).
    ap.add_argument("--ttl-days", type=int, default=TTL_DAYS)
    ap.add_argument("--min-staging-hours", type=int, default=MIN_STAGING_HOURS)
    ap.add_argument("--min-staging-matches", type=int, default=MIN_STAGING_MATCHES)
    ap.add_argument("--max-human-share", type=float, default=MAX_HUMAN_SHARE)
    ap.add_argument("--min-events", type=int, default=MIN_EVENTS)
    ap.add_argument("--min-days-promote", type=int, default=MIN_DAYS_PROMOTE)
    # D12 challenge solve-rate thresholds (calibration-only; tune on real data).
    ap.add_argument("--min-challenge-issued", type=int, default=MIN_CHALLENGE_ISSUED)
    ap.add_argument("--low-solve-rate", type=float, default=LOW_SOLVE_RATE)
    ap.add_argument("--human-solve-rate", type=float, default=HUMAN_SOLVE_RATE)
    ap.add_argument("--source", choices=("loki", "docker"), default=SOURCE,
                    help="event source (default loki; docker = edge container)")
    ap.add_argument("--hours", type=int, default=None,
                    help="fetch window in hours (default 25, or ≥min-staging-hours)")
    args = ap.parse_args()

    MAX_HUMAN_SHARE = args.max_human_share
    MIN_EVENTS = args.min_events
    MIN_DAYS_PROMOTE = args.min_days_promote
    MIN_STAGING_MATCHES = args.min_staging_matches
    MIN_CHALLENGE_ISSUED = args.min_challenge_issued
    LOW_SOLVE_RATE = args.low_solve_rate
    HUMAN_SOLVE_RATE = args.human_solve_rate

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    # The staging-observation view needs a window ≥ min-staging-hours; other
    # views default to ~25h (the report window + margin).
    fetch_hours = args.hours
    if fetch_hours is None:
        fetch_hours = (max(args.min_staging_hours + 2, FETCH_HOURS_DEFAULT)
                       if args.staging_observation_json else FETCH_HOURS_DEFAULT)
    events_all, blocklist_size, init_ts, per_source = fetch_events(args.source, fetch_hours)
    seen = load_seen()
    ip_cache = load_ip_cache()
    # IPs active at load time, BEFORE seeding fills ip_cache with every windowed
    # IP — the lazy restore below uses this to look up only IPs that weren't
    # already active (the rest can't be in the archive, so skip the disk scan).
    pre_seed_ips = set(ip_cache)
    now_utc = datetime.now(timezone.utc)
    today_str = now_utc.astimezone().strftime("%Y-%m-%d")
    events_24h = split_24h(events_all, now_utc)
    gen = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Seed ip_cache (asn/country/hosting) from the edge-logged fields up front so
    # EVERY path below — --candidates-json, --subject, the full report — sees a
    # populated cache (bot classification + DC-ASN score depend on it). Local and
    # cheap (no network), so no reason to gate it per-branch.
    seed_ip_cache_from_log(events_24h, ip_cache)

    # Loki carries no resty init marker, so _fetch_loki can't report the enforced
    # blocklist size — derive it from the catalog's active entries instead, else
    # the report's mode line would falsely read SHADOW under the Loki source.
    if args.source == "loki":
        blocklist_size = sum(1 for s in _parse_blocklist_yaml().values() if s == "active")

    if args.candidates_json:
        _require_catalog()
        high, medium, low = find_blocklist_candidates(events_24h, ip_cache, seen)
        sys.stdout.write(json.dumps({
            "generated_utc": gen,
            "thresholds": {"max_human_share": MAX_HUMAN_SHARE,
                           "min_events": MIN_EVENTS,
                           "min_days_promote": MIN_DAYS_PROMOTE,
                           "min_challenge_issued": MIN_CHALLENGE_ISSUED,
                           "low_solve_rate": LOW_SOLVE_RATE,
                           "human_solve_rate": HUMAN_SOLVE_RATE},
            "high": high, "medium": medium, "low": low,
        }, ensure_ascii=False, indent=2) + "\n")
        return 0

    if args.stale_blocklist_json:
        _require_catalog()
        sys.stdout.write(json.dumps({
            "generated_utc": gen, "ttl_days": args.ttl_days,
            "stale": find_stale_blocklist_entries(seen, now_utc, args.ttl_days),
        }, ensure_ascii=False, indent=2) + "\n")
        return 0

    if args.staging_observation_json:
        _require_catalog()
        # Observation needs a window ≥ min_staging_hours; events_all is the full
        # fetched window (~24h on docker source, widened on the Loki source).
        # since_map gives true staging dwell, independent of the window span.
        since_map = _reconcile_staging_since(now_utc)
        sys.stdout.write(json.dumps({
            "generated_utc": gen, "min_staging_hours": args.min_staging_hours,
            "min_matches": MIN_STAGING_MATCHES,
            "observations": find_staging_observation(events_all, now_utc,
                                                     args.min_staging_hours, since_map),
        }, ensure_ascii=False, indent=2) + "\n")
        return 0

    if args.subject:
        sLT = collect_lifetime_stats(seen, ip_cache)
        sys.stdout.write(render_subject(events_24h, seen, sLT, ip_cache, now_utc) + "\n")
        return 0

    # Lazy restore (D7): a fp/IP that reappears in this window but was archived
    # by rotate-state.py is pulled back into the active state with its history
    # intact, BEFORE the accumulation below adds the new window onto it. Only the
    # full-report path does this (and then persists) — the read-only JSON views
    # above return early and must not mutate the archive without saving. fps key
    # the archive; for IPs (re-seeded fresh each run) we fold the archived count
    # back into the seeded entry rather than overwrite its fresh enrichment.
    win_fps = {e["fp"] for e in events_24h if e.get("fp")}
    seen.update(restore_from_archive("fps", win_fps - seen.keys()))
    # Only IPs not already active before seeding can possibly be in the archive
    # (a record is either active or archived, never both) — restrict the lookup
    # to those so we don't scan shards for every windowed IP. Their seeded entry
    # has count=0, so folding the archived count back in restores the history.
    win_ips = {e["remote"] for e in events_24h
               if e.get("remote") and e["remote"] != "-"}
    for ip, entry in restore_from_archive("ips", win_ips - pre_seed_ips).items():
        cur = ip_cache.get(ip)
        if isinstance(cur, dict) and "error" not in cur:
            cur["count"] = cur.get("count", 0) + entry.get("count", 0)
            if entry.get("last_seen"):
                cur["last_seen"] = max(cur.get("last_seen", ""), entry["last_seen"])
        else:
            ip_cache[ip] = entry

    # Update lifetime state only for events strictly newer than the
    # watermark, so overlapping/repeated runs (cron's 25h window + manual
    # runs) don't double-count. The windowed report above already reflects
    # all of events_24h — only the cumulative counters are gated. Day
    # attribution uses the event's own timestamp, not today_str, so a
    # late-arriving event from yesterday lands on the right day.
    watermark = load_watermark()
    new_events = [e for e in events_24h
                  if e.get("ts_dt") and (watermark is None or e["ts_dt"] > watermark)]
    for e in new_events:
        fp = e["fp"]
        ev_day = e["ts_dt"].astimezone().strftime("%Y-%m-%d")
        if fp not in seen:
            seen[fp] = {
                "first_seen": e["ts"],
                "first_ua": e["ua"][:200],
                "first_remote": e["remote"],
                "count": 1,
                "days_seen": [ev_day],
            }
        else:
            seen[fp]["count"] = seen[fp].get("count", 0) + 1
            days = set(seen[fp].get("days_seen", []))
            days.add(ev_day)
            seen[fp]["days_seen"] = sorted(days)
        # D12: accumulate the solve-rate signal lifetime per-fp, counting only
        # active-host, attack-off events (§A). Same watermark dedup as `count`.
        if _is_signal_event(e):
            if e.get("verdict") == "challenge":
                seen[fp]["challenge_issued"] = seen[fp].get("challenge_issued", 0) + 1
            elif e.get("verdict") == "allow" and e.get("rule") == "challenge_pass":
                seen[fp]["challenge_solved"] = seen[fp].get("challenge_solved", 0) + 1
        ip = e["remote"]
        if ip in ip_cache and "error" not in ip_cache[ip]:
            ip_cache[ip]["count"] = ip_cache[ip].get("count", 0) + 1
            # The IP rotation clock (D7): newest day this IP was counted.
            ip_cache[ip]["last_seen"] = max(
                ip_cache[ip].get("last_seen", ""), ev_day)

    # Advance the watermark to the newest event in the window (never
    # regress it, even if old events have since aged out).
    newest = max((e["ts_dt"] for e in events_24h if e.get("ts_dt")), default=None)
    if watermark and (newest is None or watermark > newest):
        newest = watermark
    save_seen(seen)
    save_ip_cache(ip_cache)
    save_watermark(newest)

    md_report = render_markdown(events_24h, seen, blocklist_size, ip_cache, init_ts, now_utc, per_source, source=args.source)
    archive = REPORTS_DIR / f"{today_str}.md"
    archive.write_text(md_report)

    # Cache the subject line so the report wrapper (backend run.sh) gets it
    # without a second invocation (which would re-fetch the logs). Written on
    # every full run; run.sh reads state/last-subject.txt.
    sLT = collect_lifetime_stats(seen, ip_cache)
    (STATE_DIR / "last-subject.txt").write_text(
        render_subject(events_24h, seen, sLT, ip_cache, now_utc) + "\n")

    if args.html:
        # HTML renderer keeps the resty-only signature for now; comparison
        # info is in the markdown report archived under reports/.
        sys.stdout.write(render_html(events_24h, seen, blocklist_size, ip_cache, init_ts, now_utc, source=args.source))
    else:
        sys.stdout.write(md_report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
