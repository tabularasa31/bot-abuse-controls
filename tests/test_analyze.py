"""Unit tests for infra/demo-stand/scripts/analyze.py (D8).

Focus: the log-derived ip_cache seeding (the fix that replaced the external
geo-IP API), the per-ASN table it feeds, the container-start relabel (#3), and
a few core purity/classification helpers. Pure-function level — no network, no
Loki, no docker.

Run: pytest -q tests/test_analyze.py
"""

import importlib.util
from datetime import datetime, timezone
from pathlib import Path

import pytest

ANALYZE = Path(__file__).resolve().parents[1] / "infra/demo-stand/scripts/analyze.py"


def _load():
    spec = importlib.util.spec_from_file_location("analyze_under_test", ANALYZE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


az = _load()


def _ev(**kw):
    """A BAC_LOG-shaped event dict with sane defaults; override per test."""
    base = dict(
        remote="9.9.9.9", asn=None, geo_country=None, fp="L13d1_aaaa_bbbb",
        ua_family="(empty)", cipher_count=99, hash_tail="zz", cipher_hash="yy",
        uri="/", ua="-", verdict="pass",
    )
    base.update(kw)
    return base


@pytest.fixture
def dc_catalog(tmp_path, monkeypatch):
    """Point the module at a temp catalogs dir holding one DC ASN (with a
    Cyrillic comment, to exercise the utf-8 read)."""
    (tmp_path / "asn_datacenters.yaml").write_text(
        "- 15169  # Гугл ДЦ\n- 24940  # Hetzner\n", encoding="utf-8")
    monkeypatch.setattr(az, "CATALOGS_DIR", tmp_path)
    return tmp_path


# --- _load_asn_datacenters -------------------------------------------------

def test_load_asn_datacenters_parses_and_utf8(dc_catalog):
    assert az._load_asn_datacenters() == {"15169", "24940"}


def test_load_asn_datacenters_missing_file_is_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(az, "CATALOGS_DIR", tmp_path)  # no yaml present
    assert az._load_asn_datacenters() == set()


# --- seed_ip_cache_from_log ------------------------------------------------

def test_seed_populates_asn_country_hosting(dc_catalog):
    cache = {}
    az.seed_ip_cache_from_log(
        [_ev(remote="8.8.8.8", asn="15169", geo_country="US"),
         _ev(remote="1.1.1.1", asn="13335", geo_country="AU")],
        cache)
    assert cache["8.8.8.8"] == {"asn": "15169", "country": "US",
                                "hosting": True, "count": 0, "source": "log"}
    # 13335 is not in the DC catalog -> hosting False
    assert cache["1.1.1.1"]["hosting"] is False


def test_seed_skips_events_without_asn(dc_catalog):
    cache = {}
    az.seed_ip_cache_from_log([_ev(remote="5.5.5.5", asn=None)], cache)
    assert "5.5.5.5" not in cache


def test_seed_preserves_count_on_good_entry_resets_on_error(dc_catalog):
    cache = {"8.8.8.8": {"asn": "15169", "count": 5, "source": "log"},
             "2.2.2.2": {"error": "boom", "count": 0}}
    az.seed_ip_cache_from_log(
        [_ev(remote="8.8.8.8", asn="15169"), _ev(remote="2.2.2.2", asn="13335")],
        cache)
    assert cache["8.8.8.8"]["count"] == 5        # accumulated count kept
    assert cache["2.2.2.2"]["count"] == 0        # prior error -> reset
    assert "error" not in cache["2.2.2.2"]


def test_per_asn_table_populated_after_seed(dc_catalog):
    """The bug: with enrichment failing every row was '(нет данных)'. After the
    fix the logged asn drives the table; only asn-less events fall through."""
    events = [_ev(remote="8.8.8.8", asn="15169", geo_country="US"),
              _ev(remote="8.8.8.8", asn="15169", geo_country="US"),
              _ev(remote="7.7.7.7", asn=None)]
    cache = {}
    az.seed_ip_cache_from_log(events, cache)
    asns = az.collect_window_stats(events, cache)["asns"]
    assert asns[("15169", True, "US")] == 2
    assert asns[("(нет данных)", False, "")] == 1


# --- _container_start_str (#3) ---------------------------------------------

def test_container_start_relabel_loki():
    assert "Loki" in az._container_start_str(None, "loki")


def test_container_start_unknown_docker():
    assert az._container_start_str(None, "docker") == "(неизвестно)"


def test_container_start_renders_timestamp_when_known():
    ts = datetime(2026, 5, 30, 12, 0, tzinfo=timezone.utc)
    # _container_start_str converts to local time; derive the expected date the
    # same way so the test is stable in any runner timezone (a fixed UTC date
    # can roll over under astimezone() east of UTC).
    expected_date = ts.astimezone().strftime("%Y-%m-%d")
    assert expected_date in az._container_start_str(ts, "loki")


# --- purity / classification ------------------------------------------------

def test_is_genuine_browser_true_for_browser_shaped():
    fam = sorted(az.BROWSER_UA_FAMILIES)[0]
    cc = sorted(az.BROWSER_CIPHER_COUNTS)[0]
    ev = _ev(ua_family=fam, cipher_count=cc, hash_tail="not_a_tool",
             cipher_hash="not_a_tool")
    assert az.is_genuine_browser(ev) is True


def test_is_genuine_browser_false_for_nonbrowser_cipher_count():
    fam = sorted(az.BROWSER_UA_FAMILIES)[0]
    ev = _ev(ua_family=fam, cipher_count=99, hash_tail="x", cipher_hash="y")
    assert az.is_genuine_browser(ev) is False


def test_human_share_weights_genuine_fraction():
    fam = sorted(az.BROWSER_UA_FAMILIES)[0]
    cc = sorted(az.BROWSER_CIPHER_COUNTS)[0]
    genuine = _ev(ua_family=fam, cipher_count=cc, hash_tail="t", cipher_hash="t")
    botlike = _ev(ua_family="(empty)", cipher_count=99)
    assert az.human_share([genuine, botlike]) == pytest.approx(0.5)
    assert az.human_share([]) == 0.0


# --- lifetime-state rotation (D7) ------------------------------------------

from datetime import timedelta  # noqa: E402


@pytest.fixture
def state(tmp_path, monkeypatch):
    """Point the module's state paths at a temp dir so rotate/archive/restore
    operate in isolation."""
    monkeypatch.setattr(az, "STATE_DIR", tmp_path)
    monkeypatch.setattr(az, "SEEN_FPS", tmp_path / "seen-fps.json")
    monkeypatch.setattr(az, "IP_CACHE", tmp_path / "ip-cache.json")
    monkeypatch.setattr(az, "STATE_ARCHIVE_DIR", tmp_path / "archive")
    return tmp_path


def _day(n):
    return (datetime.now(timezone.utc).astimezone().date()
            - timedelta(days=n)).strftime("%Y-%m-%d")


def test_fp_last_seen_prefers_days_seen():
    assert az._fp_last_seen({"days_seen": ["2026-01-02", "2026-03-04"]}) == "2026-03-04"
    # falls back to last_seen, then first_seen (day only)
    assert az._fp_last_seen({"last_seen": "2026-05-06T00:00:00Z"}) == "2026-05-06"
    assert az._fp_last_seen({"first_seen": "2026-07-08T09:00:00Z"}) == "2026-07-08"
    assert az._fp_last_seen({}) is None


def test_rotate_archives_old_drops_weak_keeps_recent(state):
    az.save_seen({
        "old_strong": {"count": 50, "days_seen": [_day(40)], "first_seen": _day(40)},
        "recent": {"count": 50, "days_seen": [_day(2)], "first_seen": _day(2)},
        "old_weak": {"count": 1, "days_seen": [_day(20)], "first_seen": _day(20)},
        "no_clock": {"count": 5},
    })
    az.save_ip_cache({})
    summary = az.rotate_state(fp_ttl=30, ip_ttl=7, min_count=3)
    assert summary["fps"] == {"archived": 1, "dropped": 1, "kept": 2}
    import json
    active = json.loads((state / "seen-fps.json").read_text())
    assert set(active) == {"recent", "no_clock"}      # old_weak dropped, no_clock kept (no clock)
    # old_strong archived under its last-seen month, recoverable
    restored = az.restore_from_archive("fps", {"old_strong"})
    assert restored["old_strong"]["count"] == 50


def test_restore_removes_from_archive(state):
    az.save_seen({"x": {"count": 9, "days_seen": [_day(40)], "first_seen": _day(40)}})
    az.save_ip_cache({})
    az.rotate_state(fp_ttl=30)
    assert az.restore_from_archive("fps", {"x"})       # first restore finds it
    assert az.restore_from_archive("fps", {"x"}) == {}  # gone from the shard now


def test_restore_empty_keys_is_noop(state):
    assert az.restore_from_archive("fps", set()) == {}


def test_ip_rotation_uses_last_seen_and_keeps_unclocked(state):
    az.save_seen({})
    az.save_ip_cache({
        "old": {"asn": "1", "country": "US", "hosting": False, "count": 9, "last_seen": _day(20)},
        "fresh": {"asn": "2", "country": "US", "hosting": True, "count": 9, "last_seen": _day(1)},
        "unclocked": {"asn": "3", "country": "US", "hosting": False, "count": 9},
    })
    summary = az.rotate_state(fp_ttl=30, ip_ttl=7, min_count=3)
    assert summary["ips"] == {"archived": 1, "dropped": 0, "kept": 2}
    import json
    active = json.loads((state / "ip-cache.json").read_text())
    assert set(active) == {"fresh", "unclocked"}


def test_seed_preserves_last_seen_when_present(dc_catalog):
    cache = {"8.8.8.8": {"asn": "15169", "count": 5, "source": "log",
                         "last_seen": "2026-05-01"}}
    az.seed_ip_cache_from_log([_ev(remote="8.8.8.8", asn="15169")], cache)
    assert cache["8.8.8.8"]["last_seen"] == "2026-05-01"
    assert cache["8.8.8.8"]["count"] == 5
