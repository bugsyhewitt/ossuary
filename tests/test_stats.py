"""Tests for the engagement summary command (POST_V01 Rank 10 — `ossuary stats`).

The summary is a top-of-funnel roll-up over the same assets/services/findings
data `dump` reads: totals, KEV count, EPSS/severity tier breakdowns, and the
leading findings in `match-cves` triage order. No network, no new schema.
"""

from __future__ import annotations

import json

import pytest

from ossuary import db, stats


def _seed_mixed(db_path):
    """One asset, two services, findings spanning every signal tier.

    svc-80 (nginx): a hot KEV/high-EPSS/critical CVE, plus a cold one.
    svc-22 (ssh):   a mid-severity, no-EPSS, non-KEV CVE.
    """
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        s80 = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
        s22 = db.upsert_service(conn, aid, 22, "tcp", "ssh", "OpenSSH", "8.2", None)
        db.upsert_finding(conn, s80, "CVE-HOT", "exploited", "9.8",
                          epss_score=0.94, kev=1)
        db.upsert_finding(conn, s80, "CVE-COLD", "theoretical", "3.1",
                          epss_score=0.02, kev=0)
        db.upsert_finding(conn, s22, "CVE-MID", "needs auth", "6.5",
                          epss_score=None, kev=0)
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------
# build_stats — the underlying numbers
# --------------------------------------------------------------------------

def test_stats_counts_assets_services_findings(db_path):
    _seed_mixed(db_path)
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn)
    finally:
        conn.close()
    assert summary["assets"] == 1
    assert summary["services"] == 2
    assert summary["findings"] == 3


def test_stats_counts_kev(db_path):
    _seed_mixed(db_path)
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn)
    finally:
        conn.close()
    assert summary["kev"] == 1


def test_stats_epss_tiers(db_path):
    _seed_mixed(db_path)
    conn = db.require_initialised(db_path)
    try:
        tiers = stats.build_stats(conn)["epss_tiers"]
    finally:
        conn.close()
    # CVE-HOT 0.94 -> high, CVE-COLD 0.02 -> low, CVE-MID None -> unscored.
    assert tiers == {"high": 1, "medium": 0, "low": 1, "unscored": 1}


def test_stats_severity_tiers(db_path):
    _seed_mixed(db_path)
    conn = db.require_initialised(db_path)
    try:
        tiers = stats.build_stats(conn)["severity_tiers"]
    finally:
        conn.close()
    # 9.8 -> critical, 6.5 -> medium, 3.1 -> low.
    assert tiers == {"critical": 1, "high": 0, "medium": 1, "low": 1, "blank": 0}


def test_stats_blank_severity_tier(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, sid, "CVE-BLANK", "x", None, epss_score=None, kev=0)
        conn.commit()
    finally:
        conn.close()
    conn = db.require_initialised(db_path)
    try:
        tiers = stats.build_stats(conn)["severity_tiers"]
    finally:
        conn.close()
    assert tiers["blank"] == 1


def test_stats_top_findings_are_triage_ordered(db_path):
    _seed_mixed(db_path)
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn)
    finally:
        conn.close()
    ids = [f["cve_id"] for f in summary["top_findings"]]
    # KEV first, then by EPSS desc; CVE-MID (no EPSS) sinks below CVE-COLD.
    assert ids == ["CVE-HOT", "CVE-COLD", "CVE-MID"]


def test_stats_top_limit_bounds_findings_list(db_path):
    _seed_mixed(db_path)
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn, top=1)
    finally:
        conn.close()
    assert [f["cve_id"] for f in summary["top_findings"]] == ["CVE-HOT"]


def test_stats_top_zero_omits_findings_list(db_path):
    _seed_mixed(db_path)
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn, top=0)
    finally:
        conn.close()
    assert summary["top_findings"] == []
    # counts are unaffected by the top limit
    assert summary["findings"] == 3


def test_stats_empty_db_is_all_zeros(db_path):
    db.init_db(db_path).close()
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn)
    finally:
        conn.close()
    assert summary["assets"] == 0
    assert summary["services"] == 0
    assert summary["findings"] == 0
    assert summary["kev"] == 0
    assert summary["top_findings"] == []
    assert summary["epss_tiers"] == {"high": 0, "medium": 0, "low": 0, "unscored": 0}


# --------------------------------------------------------------------------
# stats() — format serialisation
# --------------------------------------------------------------------------

def test_stats_json_format_matches_build(db_path):
    _seed_mixed(db_path)
    conn = db.require_initialised(db_path)
    try:
        expected = stats.build_stats(conn)
    finally:
        conn.close()
    out = json.loads(stats.stats(db_path, "json"))
    assert out == expected


def test_stats_text_format_reports_headline_numbers(db_path):
    _seed_mixed(db_path)
    out = stats.stats(db_path, "text")
    assert "assets:   1" in out
    assert "services: 2" in out
    assert "findings: 3" in out
    assert "KEV (actively exploited): 1" in out
    # leading finding appears in the top list
    assert "CVE-HOT" in out


def test_stats_text_empty_db_says_none(db_path):
    db.init_db(db_path).close()
    out = stats.stats(db_path, "text")
    assert "top findings by priority: none" in out


def test_stats_rejects_unknown_format(db_path):
    db.init_db(db_path).close()
    with pytest.raises(ValueError, match="unsupported stats format"):
        stats.stats(db_path, "yaml")


def test_stats_uninitialised_db_raises(tmp_path):
    with pytest.raises(RuntimeError, match="not initialised"):
        stats.stats(tmp_path / "missing.db", "text")
