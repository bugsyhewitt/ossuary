"""Tests for age-staleness flagging (`ossuary stale`, POST_V01 Rank 17).

`stale` flags findings whose `matched_at` is older than a day threshold relative
to "now" — findings not re-confirmed by a recent scan. These tests pin
`matched_at` to fixed timestamps so the age comparison is deterministic, and
drive the boundary, ordering, filter-composition, and format behaviour. No test
touches the network.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from ossuary import cli, db, stale


# A fixed reference "now" so every age computation in these tests is stable.
NOW = datetime(2026, 5, 29, 12, 0, 0, tzinfo=timezone.utc)


def _set_matched_at(db_path, service_id, cve_id, when):
    """Force a finding's stored matched_at to a fixed timestamp string."""
    conn = db.require_initialised(db_path)
    try:
        conn.execute(
            "UPDATE findings SET matched_at = ? WHERE service_id = ? AND cve_id = ?",
            (when, service_id, cve_id),
        )
        conn.commit()
    finally:
        conn.close()


def _seed(db_path):
    """Seed one asset/service with three findings at known ages.

    Returns the service id so tests can override matched_at values.
    Ages relative to NOW (2026-05-29):
      * CVE-OLD     last seen 2026-03-01  -> ~89 days old (stale at default 30d)
      * CVE-RECENT  last seen 2026-05-25  -> ~4 days old  (fresh at default 30d)
      * CVE-EDGE    last seen 2026-04-29  -> exactly 30 days old (boundary)
    """
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
        db.upsert_finding(conn, sid, "CVE-OLD", "old one", "9.8", epss_score=0.9, kev=1)
        db.upsert_finding(conn, sid, "CVE-RECENT", "recent one", "2.0")
        db.upsert_finding(conn, sid, "CVE-EDGE", "edge one", "5.0", epss_score=0.2)
        conn.commit()
    finally:
        conn.close()
    _set_matched_at(db_path, sid, "CVE-OLD", "2026-03-01 12:00:00")
    _set_matched_at(db_path, sid, "CVE-RECENT", "2026-05-25 12:00:00")
    _set_matched_at(db_path, sid, "CVE-EDGE", "2026-04-29 12:00:00")
    return sid


def _build(db_path, **kwargs):
    conn = db.require_initialised(db_path)
    try:
        return stale.build_stale(conn, now=NOW, **kwargs)
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Core staleness behaviour
# --------------------------------------------------------------------------

def test_flags_findings_older_than_threshold(db_path):
    _seed(db_path)
    report = _build(db_path, max_age_days=30)
    cves = {f["cve_id"] for f in report["stale"]}
    # OLD (89d) and EDGE (exactly 30d) are stale; RECENT (4d) is not.
    assert cves == {"CVE-OLD", "CVE-EDGE"}
    assert report["count"] == 2


def test_recent_finding_not_flagged(db_path):
    _seed(db_path)
    report = _build(db_path, max_age_days=30)
    assert "CVE-RECENT" not in {f["cve_id"] for f in report["stale"]}


def test_boundary_exactly_at_threshold_is_stale(db_path):
    _seed(db_path)
    # EDGE is exactly 30 days old; with max_age_days=30 it is flagged (<= cutoff).
    report = _build(db_path, max_age_days=30)
    assert "CVE-EDGE" in {f["cve_id"] for f in report["stale"]}


def test_just_under_threshold_is_fresh(db_path):
    _seed(db_path)
    # Raising the threshold to 31 days drops the 30-day-old EDGE finding.
    report = _build(db_path, max_age_days=31)
    assert "CVE-EDGE" not in {f["cve_id"] for f in report["stale"]}
    assert {f["cve_id"] for f in report["stale"]} == {"CVE-OLD"}


def test_large_threshold_flags_nothing(db_path):
    _seed(db_path)
    report = _build(db_path, max_age_days=1000)
    assert report["count"] == 0
    assert report["stale"] == []


def test_zero_threshold_flags_all_dated_findings(db_path):
    _seed(db_path)
    report = _build(db_path, max_age_days=0)
    assert report["count"] == 3


# --------------------------------------------------------------------------
# Ordering and reported detail
# --------------------------------------------------------------------------

def test_ordered_oldest_first(db_path):
    _seed(db_path)
    report = _build(db_path, max_age_days=0)
    cve_order = [f["cve_id"] for f in report["stale"]]
    # OLD (89d) before EDGE (30d) before RECENT (4d).
    assert cve_order == ["CVE-OLD", "CVE-EDGE", "CVE-RECENT"]


def test_age_days_is_computed(db_path):
    _seed(db_path)
    report = _build(db_path, max_age_days=0)
    by_cve = {f["cve_id"]: f for f in report["stale"]}
    assert by_cve["CVE-EDGE"]["age_days"] == pytest.approx(30.0, abs=0.01)
    assert by_cve["CVE-RECENT"]["age_days"] == pytest.approx(4.0, abs=0.01)


def test_entry_carries_location_and_signal(db_path):
    _seed(db_path)
    report = _build(db_path, max_age_days=30)
    old = next(f for f in report["stale"] if f["cve_id"] == "CVE-OLD")
    assert old["ip"] == "10.10.0.5"
    assert old["hostname"] == "host-a"
    assert old["port"] == 80
    assert old["protocol"] == "tcp"
    assert old["kev"] == 1
    assert old["epss_score"] == 0.9


# --------------------------------------------------------------------------
# Missing matched_at handling
# --------------------------------------------------------------------------

def test_finding_with_no_matched_at_is_flagged(db_path):
    sid = _seed(db_path)
    _set_matched_at(db_path, sid, "CVE-RECENT", "")
    report = _build(db_path, max_age_days=30)
    by_cve = {f["cve_id"]: f for f in report["stale"]}
    assert "CVE-RECENT" in by_cve
    assert by_cve["CVE-RECENT"]["age_days"] is None


def test_unknown_age_sorts_last(db_path):
    sid = _seed(db_path)
    _set_matched_at(db_path, sid, "CVE-RECENT", "")
    report = _build(db_path, max_age_days=0)
    assert report["stale"][-1]["cve_id"] == "CVE-RECENT"


# --------------------------------------------------------------------------
# Filter / tag composition (reuses dump.build_state)
# --------------------------------------------------------------------------

def test_kev_only_scopes_candidates(db_path):
    _seed(db_path)
    report = _build(db_path, max_age_days=30, kev_only=True)
    assert {f["cve_id"] for f in report["stale"]} == {"CVE-OLD"}


def test_min_epss_scopes_candidates(db_path):
    _seed(db_path)
    # EPSS floor 0.5 keeps only CVE-OLD (0.9); EDGE (0.2) and RECENT (None) drop.
    report = _build(db_path, max_age_days=0, min_epss=0.5)
    assert {f["cve_id"] for f in report["stale"]} == {"CVE-OLD"}


def test_min_severity_scopes_candidates(db_path):
    _seed(db_path)
    report = _build(db_path, max_age_days=0, min_severity=5.0)
    # OLD (9.8) and EDGE (5.0) clear; RECENT (2.0) does not.
    assert {f["cve_id"] for f in report["stale"]} == {"CVE-OLD", "CVE-EDGE"}


def test_tag_scopes_candidates(db_path):
    sid = _seed(db_path)
    # Add a second tagged asset with a stale finding; untagged stays out.
    conn = db.require_initialised(db_path)
    try:
        bid = db.upsert_asset(conn, "10.10.0.6", "host-b", "up")
        sid_b = db.upsert_service(conn, bid, 443, "tcp", "https", "apache", "2.4.0", None)
        db.upsert_finding(conn, sid_b, "CVE-TAGGED", "tagged one", "7.0")
        conn.commit()
    finally:
        conn.close()
    _set_matched_at(db_path, sid_b, "CVE-TAGGED", "2026-01-01 12:00:00")
    from ossuary import tags
    tags.add_tag(db_path, "10.10.0.6", "in-scope")

    report = _build(db_path, max_age_days=30, tag="in-scope")
    assert {f["cve_id"] for f in report["stale"]} == {"CVE-TAGGED"}


# --------------------------------------------------------------------------
# Report metadata + formats
# --------------------------------------------------------------------------

def test_report_metadata_present(db_path):
    _seed(db_path)
    report = _build(db_path, max_age_days=30)
    assert report["max_age_days"] == 30
    assert report["as_of"] == "2026-05-29 12:00:00"
    assert report["count"] == len(report["stale"])


def test_json_format_round_trips(db_path):
    # Uses real "now"; CVE-OLD (2026-03-01) is comfortably > 30 days old for any
    # run on/after this lap's date, while CVE-RECENT (2026-05-25) is not. Assert
    # on those two unambiguous cases rather than the day-boundary EDGE finding.
    _seed(db_path)
    out = stale.stale(db_path, "json", max_age_days=30)
    parsed = json.loads(out)
    cves = {f["cve_id"] for f in parsed["stale"]}
    assert "CVE-OLD" in cves
    assert "CVE-RECENT" not in cves


def test_text_format_lists_stale_findings(db_path):
    _seed(db_path)
    out = stale.stale(db_path, "text", max_age_days=30)
    assert "stale findings" in out
    assert "CVE-OLD" in out
    assert "CVE-RECENT" not in out


def test_text_format_empty_report(db_path):
    _seed(db_path)
    out = stale.stale(db_path, "text", max_age_days=1000)
    assert "count: 0" in out
    assert "none" in out


def test_rejects_unknown_format(db_path):
    db.init_db(db_path).close()
    with pytest.raises(ValueError, match="unsupported stale format"):
        stale.stale(db_path, "yaml")


def test_rejects_negative_age(db_path):
    db.init_db(db_path).close()
    with pytest.raises(ValueError, match="non-negative"):
        stale.stale(db_path, "text", max_age_days=-1)


def test_empty_db_is_valid(db_path):
    db.init_db(db_path).close()
    out = stale.stale(db_path, "json", max_age_days=30)
    parsed = json.loads(out)
    assert parsed["count"] == 0
    assert parsed["stale"] == []


# --------------------------------------------------------------------------
# CLI wiring
# --------------------------------------------------------------------------

def test_cli_stale_runs(db_path, capsys):
    _seed(db_path)
    rc = cli.main(["stale", "--db", str(db_path), "--format", "json"])
    assert rc == 0
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert "stale" in parsed


def test_cli_stale_max_age_flag(db_path, capsys):
    _seed(db_path)
    rc = cli.main(
        ["stale", "--db", str(db_path), "--format", "json", "--max-age-days", "1000"]
    )
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["count"] == 0


def test_cli_stale_kev_only_flag(db_path, capsys):
    _seed(db_path)
    rc = cli.main(
        ["stale", "--db", str(db_path), "--format", "json", "--kev-only"]
    )
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert {f["cve_id"] for f in parsed["stale"]} == {"CVE-OLD"}
