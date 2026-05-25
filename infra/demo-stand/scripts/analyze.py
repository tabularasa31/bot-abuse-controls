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
SEEN_FPS = STATE_DIR / "seen-fps.json"
IP_CACHE = STATE_DIR / "ip-cache.json"
# Pre-recreate log snapshots. update.sh dumps `docker logs` here before
# rebuilding the container (a recreate drops the container's docker-json log
# history). We fold these back in so a rebuild deploy leaves no gap.
ARCHIVE_DIR = STATE_DIR / "bac-archive"

# The stand's container. It emits one Phase 1 `BAC_LOG {json}` record per
# request to docker stdout.
CONTAINER = os.environ.get("BAC_CONTAINER", "nginx-demo")

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
    r"/\.well-known/security\.txt|"
    r"/cgi-bin|/shell|/eval|/cmd)",
    re.I,
)

IPAPI_BATCH = (
    "https://ip-api.com/batch?fields="
    "status,country,countryCode,city,isp,org,as,asname,reverse,hosting,query"
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
    d = {
        "fp": fp,
        "verdict": rec.get("verdict") or "pass",
        "status": str(status) if status is not None else "-",
        "uri": rec.get("path") or "-",
        "remote": rec.get("ip") or "-",
        "ua": rec.get("ua") or "-",
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


def fetch_events():
    """Pull events from the stand's container, merged with any pre-recreate
    archives so a rebuild deploy leaves no gap. A missing/dead container yields
    an empty (archive-only) report rather than an error. The 4th return value
    (per_source) is kept None so the renderers' optional comparison block stays
    inert — this stand has a single source."""
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


def enrich_ips(ips, cache):
    to_query = sorted({ip for ip in ips if ip and ip not in cache})
    if not to_query:
        return
    for chunk_start in range(0, len(to_query), 100):
        chunk = to_query[chunk_start:chunk_start + 100]
        body = json.dumps([{"query": ip} for ip in chunk]).encode()
        req = urllib.request.Request(
            IPAPI_BATCH,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "abuse-controls-demo/1.0 (https://bac.example.com)",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                results = json.loads(resp.read())
        except Exception as e:
            err = str(e)[:120]
            for ip in chunk:
                cache[ip] = {"error": err, "count": 0}
            continue
        for r in results if isinstance(results, list) else []:
            ip = r.get("query")
            if not ip:
                continue
            if r.get("status") == "success":
                cache[ip] = {
                    "country": r.get("countryCode") or "",
                    "city": r.get("city") or "",
                    "isp": r.get("isp") or "",
                    "org": r.get("org") or "",
                    "asn": r.get("as") or "",
                    "rdns": r.get("reverse") or "",
                    "hosting": bool(r.get("hosting")),
                    "count": 0,
                }
            else:
                cache[ip] = {"error": r.get("message", "unknown"), "count": 0}


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
        score += 2
        reasons.append("suspicious cipher count vs UA +2")
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

    return score, reasons, tags


def find_blocklist_candidates(events, ip_cache, seen):
    """Return three lists: high, medium, low confidence candidates."""
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
        suggested_action = "не блокировать"
        if score >= 5:
            suggested_action = "hard block fp в blocklist.lua (HIGH confidence)"
            tier = "HIGH"
        elif score >= 3:
            suggested_action = "watch-list, не блокировать пока без 2-го дня данных"
            tier = "MEDIUM"
        else:
            tier = "LOW"
            suggested_action = "не блокировать — слабые сигналы"
        candidates.append({
            "fp": fp, "score": score, "tier": tier,
            "reasons": reasons, "tags": sorted(tags),
            "ips": sorted(ips), "n_events_24h": len(evs),
            "n_lifetime": (seen.get(fp) or {}).get("count", len(evs)),
            "days_seen": sorted(set((seen.get(fp) or {}).get("days_seen", []))),
            "uris": sorted({e["uri"] for e in evs}),
            "sample_ua": sample["ua"][:120],
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


def render_markdown(events_24h, seen, blocklist_size, ip_cache, init_ts, now_utc, per_source=None):
    s24 = collect_window_stats(events_24h, ip_cache)
    sLT = collect_lifetime_stats(seen, ip_cache)
    high, medium, low = find_blocklist_candidates(events_24h, ip_cache, seen)
    asn_watch = find_asn_watch_candidates(events_24h, ip_cache)
    now_msk = now_utc.astimezone()
    init_str = init_ts.astimezone().strftime("%Y-%m-%d %H:%M %Z") if init_ts else "(неизвестно)"

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
    L.append("- suspicious cipher count: +2")
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


def render_html(events_24h, seen, blocklist_size, ip_cache, init_ts, now_utc):
    s24 = collect_window_stats(events_24h, ip_cache)
    sLT = collect_lifetime_stats(seen, ip_cache)
    high, medium, low = find_blocklist_candidates(events_24h, ip_cache, seen)
    asn_watch = find_asn_watch_candidates(events_24h, ip_cache)
    now_msk = now_utc.astimezone()
    init_str = init_ts.astimezone().strftime("%Y-%m-%d %H:%M %Z") if init_ts else "(неизвестно)"

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
        "<strong>Скоринг:</strong> impersonator +3 · suspicious cipher +2 · automation UA +1 · "
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
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--html", action="store_true")
    g.add_argument("--subject", action="store_true")
    args = ap.parse_args()

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    events_all, blocklist_size, init_ts, per_source = fetch_events()
    seen = load_seen()
    ip_cache = load_ip_cache()
    now_utc = datetime.now(timezone.utc)
    today_str = now_utc.astimezone().strftime("%Y-%m-%d")
    events_24h = split_24h(events_all, now_utc)

    if args.subject:
        sLT = collect_lifetime_stats(seen, ip_cache)
        sys.stdout.write(render_subject(events_24h, seen, sLT, ip_cache, now_utc) + "\n")
        return 0

    enrich_ips({e["remote"] for e in events_24h}, ip_cache)

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
        ip = e["remote"]
        if ip in ip_cache and "error" not in ip_cache[ip]:
            ip_cache[ip]["count"] = ip_cache[ip].get("count", 0) + 1

    # Advance the watermark to the newest event in the window (never
    # regress it, even if old events have since aged out).
    newest = max((e["ts_dt"] for e in events_24h if e.get("ts_dt")), default=None)
    if watermark and (newest is None or watermark > newest):
        newest = watermark
    save_seen(seen)
    save_ip_cache(ip_cache)
    save_watermark(newest)

    md_report = render_markdown(events_24h, seen, blocklist_size, ip_cache, init_ts, now_utc, per_source)
    archive = REPORTS_DIR / f"{today_str}.md"
    archive.write_text(md_report)

    # Cache the subject line so daily-report.sh gets it without a second
    # invocation (which would re-fetch docker logs). Written on every full
    # run; daily-report.sh reads state/last-subject.txt.
    sLT = collect_lifetime_stats(seen, ip_cache)
    (STATE_DIR / "last-subject.txt").write_text(
        render_subject(events_24h, seen, sLT, ip_cache, now_utc) + "\n")

    if args.html:
        # HTML renderer keeps the resty-only signature for now; comparison
        # info is in the markdown report archived under reports/.
        sys.stdout.write(render_html(events_24h, seen, blocklist_size, ip_cache, init_ts, now_utc))
    else:
        sys.stdout.write(md_report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
