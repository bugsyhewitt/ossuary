"""Tests for the engagement summary command (POST_V01 Rank 10 — `ossuary stats`).

The summary is a top-of-funnel roll-up over the same assets/services/findings
data `dump` reads: totals, KEV count, EPSS/severity tier breakdowns, and the
leading findings in `match-cves` triage order. No network, no new schema.
"""

from __future__ import annotations

import json

import pytest

from ossuary import db, stats, tags


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


# --------------------------------------------------------------------------
# tag scoping — the `--tag` workflow companion to `dump --tag`
# --------------------------------------------------------------------------

def _seed_two_hosts(db_path):
    """Two assets with disjoint findings, so a tag scopes to one host's signal.

    host-a (10.10.0.5): one KEV/high-EPSS/critical finding on port 80.
    host-b (10.10.0.6): one non-KEV/low-EPSS/low finding on port 443.
    Only host-a is tagged "in-scope".
    """
    conn = db.init_db(db_path)
    try:
        a = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        b = db.upsert_asset(conn, "10.10.0.6", "host-b", "up")
        sa = db.upsert_service(conn, a, 80, "tcp", "http", "nginx", "1.18.0", None)
        sb = db.upsert_service(conn, b, 443, "tcp", "https", "nginx", "1.20.0", None)
        db.upsert_finding(conn, sa, "CVE-A", "exploited", "9.8",
                          epss_score=0.91, kev=1)
        db.upsert_finding(conn, sb, "CVE-B", "theoretical", "3.0",
                          epss_score=0.03, kev=0)
        conn.commit()
    finally:
        conn.close()
    tags.add_tag(db_path, "10.10.0.5", "in-scope")


def test_stats_tag_scopes_counts_to_tagged_asset(db_path):
    _seed_two_hosts(db_path)
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn, tag="in-scope")
    finally:
        conn.close()
    # Only host-a (and its one service / finding) is in scope.
    assert summary["assets"] == 1
    assert summary["services"] == 1
    assert summary["findings"] == 1
    assert summary["kev"] == 1


def test_stats_tag_scopes_tiers_and_top(db_path):
    _seed_two_hosts(db_path)
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn, tag="in-scope")
    finally:
        conn.close()
    # Only CVE-A's signal survives the scope; CVE-B (host-b) is excluded.
    assert summary["epss_tiers"] == {"high": 1, "medium": 0, "low": 0, "unscored": 0}
    assert summary["severity_tiers"] == {
        "critical": 1, "high": 0, "medium": 0, "low": 0, "blank": 0
    }
    assert [f["cve_id"] for f in summary["top_findings"]] == ["CVE-A"]


def test_stats_no_tag_covers_whole_engagement(db_path):
    _seed_two_hosts(db_path)
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn)
    finally:
        conn.close()
    # Without a tag, both hosts and both findings are counted.
    assert summary["assets"] == 2
    assert summary["services"] == 2
    assert summary["findings"] == 2
    assert summary["kev"] == 1


def test_stats_tag_agrees_with_scoped_dump(db_path):
    from ossuary import dump

    _seed_two_hosts(db_path)
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn, tag="in-scope")
        state = dump.build_state(conn, tag="in-scope")
    finally:
        conn.close()
    # stats counts must match what a scoped dump shows, by construction.
    dump_assets = len(state["assets"])
    dump_services = sum(len(a["services"]) for a in state["assets"])
    dump_findings = sum(
        len(s["findings"]) for a in state["assets"] for s in a["services"]
    )
    assert summary["assets"] == dump_assets
    assert summary["services"] == dump_services
    assert summary["findings"] == dump_findings


def test_stats_unknown_tag_yields_empty_summary(db_path):
    _seed_two_hosts(db_path)
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn, tag="does-not-exist")
    finally:
        conn.close()
    assert summary["assets"] == 0
    assert summary["services"] == 0
    assert summary["findings"] == 0
    assert summary["kev"] == 0
    assert summary["top_findings"] == []


def test_stats_text_tag_header_records_scope(db_path):
    _seed_two_hosts(db_path)
    out = stats.stats(db_path, "text", tag="in-scope")
    assert "engagement summary (tag: in-scope)" in out
    assert "assets:   1" in out
    assert "CVE-A" in out
    # the out-of-scope host's finding must not appear
    assert "CVE-B" not in out


def test_stats_text_no_tag_header_unchanged(db_path):
    _seed_two_hosts(db_path)
    out = stats.stats(db_path, "text")
    # the header has no scope suffix when unscoped (byte-for-byte prior shape)
    assert out.splitlines()[0] == "engagement summary"


def test_stats_json_tag_scopes_numbers(db_path):
    _seed_two_hosts(db_path)
    scoped = json.loads(stats.stats(db_path, "json", tag="in-scope"))
    full = json.loads(stats.stats(db_path, "json"))
    assert scoped["assets"] == 1
    assert full["assets"] == 2
    # the json shape carries no extra "tag" key — same structure as before
    assert set(scoped.keys()) == set(full.keys())


# --------------------------------------------------------------------------
# actionability filters — the kev-only / min-epss / min-severity companion to
# `dump`'s Rank 8 filters
# --------------------------------------------------------------------------

def test_stats_kev_only_counts_only_kev_findings(db_path):
    _seed_mixed(db_path)
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn, kev_only=True)
    finally:
        conn.close()
    # Only CVE-HOT is KEV; the cold and mid findings drop out, and so does the
    # ssh service that carried no KEV finding.
    assert summary["findings"] == 1
    assert summary["kev"] == 1
    assert summary["services"] == 1
    assert summary["assets"] == 1
    assert [f["cve_id"] for f in summary["top_findings"]] == ["CVE-HOT"]


def test_stats_min_epss_excludes_low_and_unscored(db_path):
    _seed_mixed(db_path)
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn, min_epss=0.5)
    finally:
        conn.close()
    # CVE-HOT 0.94 survives; CVE-COLD 0.02 and CVE-MID (no EPSS) are excluded.
    assert summary["findings"] == 1
    assert summary["epss_tiers"] == {"high": 1, "medium": 0, "low": 0, "unscored": 0}


def test_stats_min_severity_excludes_low_and_blank(db_path):
    _seed_mixed(db_path)
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn, min_severity=7.0)
    finally:
        conn.close()
    # Only CVE-HOT (9.8) clears 7.0; CVE-MID (6.5) and CVE-COLD (3.1) drop.
    assert summary["findings"] == 1
    assert summary["severity_tiers"] == {
        "critical": 1, "high": 0, "medium": 0, "low": 0, "blank": 0
    }


def test_stats_filters_compose(db_path):
    _seed_mixed(db_path)
    conn = db.require_initialised(db_path)
    try:
        # KEV-only AND min-severity 9.0 — CVE-HOT clears both.
        summary = stats.build_stats(conn, kev_only=True, min_severity=9.0)
    finally:
        conn.close()
    assert summary["findings"] == 1
    assert [f["cve_id"] for f in summary["top_findings"]] == ["CVE-HOT"]


def test_stats_filter_can_empty_the_summary(db_path):
    _seed_mixed(db_path)
    conn = db.require_initialised(db_path)
    try:
        # No finding has EPSS >= 0.99, so everything is pruned.
        summary = stats.build_stats(conn, min_epss=0.99)
    finally:
        conn.close()
    assert summary["assets"] == 0
    assert summary["services"] == 0
    assert summary["findings"] == 0
    assert summary["kev"] == 0
    assert summary["top_findings"] == []


def test_stats_no_filter_unchanged(db_path):
    _seed_mixed(db_path)
    conn = db.require_initialised(db_path)
    try:
        # Passing the filter params at their no-op defaults must equal the
        # historical whole-engagement summary byte-for-byte.
        baseline = stats.build_stats(conn)
        with_defaults = stats.build_stats(
            conn, min_epss=None, min_severity=None, kev_only=False
        )
    finally:
        conn.close()
    assert with_defaults == baseline


def test_stats_filters_compose_with_tag(db_path):
    _seed_two_hosts(db_path)
    conn = db.require_initialised(db_path)
    try:
        # host-a (in-scope) has the only KEV finding; host-b is out of scope.
        scoped = stats.build_stats(conn, tag="in-scope", kev_only=True)
        # the same KEV filter without the tag still sees only host-a's KEV hit
        # here, but the tag must further restrict to in-scope assets.
        out_of_scope = stats.build_stats(conn, tag="in-scope", min_epss=0.99)
    finally:
        conn.close()
    assert scoped["findings"] == 1
    assert [f["cve_id"] for f in scoped["top_findings"]] == ["CVE-A"]
    # tag + an impossible EPSS floor empties the scoped summary
    assert out_of_scope["findings"] == 0


def test_stats_filtered_agrees_with_filtered_dump(db_path):
    from ossuary import dump

    _seed_mixed(db_path)
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn, min_severity=7.0)
        state = dump.build_state(conn, min_severity=7.0)
    finally:
        conn.close()
    dump_assets = len(state["assets"])
    dump_services = sum(len(a["services"]) for a in state["assets"])
    dump_findings = sum(
        len(s["findings"]) for a in state["assets"] for s in a["services"]
    )
    assert summary["assets"] == dump_assets
    assert summary["services"] == dump_services
    assert summary["findings"] == dump_findings


def test_stats_text_header_records_kev_filter(db_path):
    _seed_mixed(db_path)
    out = stats.stats(db_path, "text", kev_only=True)
    assert out.splitlines()[0] == "engagement summary (kev-only)"


def test_stats_text_header_records_epss_and_severity_filters(db_path):
    _seed_mixed(db_path)
    out = stats.stats(db_path, "text", min_epss=0.5, min_severity=7.0)
    first = out.splitlines()[0]
    assert "epss>=0.5" in first
    assert "severity>=7" in first


def test_stats_text_header_combines_tag_and_filters(db_path):
    _seed_two_hosts(db_path)
    out = stats.stats(db_path, "text", tag="in-scope", kev_only=True)
    assert out.splitlines()[0] == "engagement summary (tag: in-scope, kev-only)"


def test_stats_json_filter_keeps_shape(db_path):
    _seed_mixed(db_path)
    filtered = json.loads(stats.stats(db_path, "json", kev_only=True))
    full = json.loads(stats.stats(db_path, "json"))
    # the filter trims numbers but the JSON structure is unchanged
    assert set(filtered.keys()) == set(full.keys())
    assert filtered["findings"] == 1
    assert full["findings"] == 3
