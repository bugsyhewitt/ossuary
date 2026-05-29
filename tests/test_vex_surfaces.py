"""Tests for VEX suppression on the stats / stale / diff read surfaces.

VEX suppression (OpenVEX `not_affected` / `fixed` rulings) shipped first on
`dump` (`dump --vex`). Every other finding-level read surface routes through
`dump.build_state`, so suppression extends to them uniformly: a finding triaged
away in a VEX document is hidden from `stats`' counts, never flagged `stale`, and
removed from both sides of a `diff` before the comparison.

These tests cover the programmatic `vex=` parameter on `stats.build_stats`,
`stale.build_stale`, and `findingdiff.build_diff`, plus the `--vex` CLI flag on
the three subcommands. They sit alongside `test_vex.py` (which covers the parser
and the `dump` integration). No test touches the network.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from ossuary import cli, db, findingdiff, stale, stats, vex


# --------------------------------------------------------------------------
# VEX document builders (mirroring test_vex.py)
# --------------------------------------------------------------------------

def _statement(cve, status, products=None):
    stmt = {"vulnerability": {"name": cve}, "status": status}
    if products is not None:
        stmt["products"] = products
    return stmt


def _vex_doc(*statements):
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://example.com/vex/test",
        "author": "tester",
        "statements": list(statements),
    }


def _write(tmp_path, doc, name="vex.json"):
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Shared seed: two hosts, each with one service carrying two findings.
# --------------------------------------------------------------------------

def _seed(db_path):
    """host-a 10.0.0.5:80 -> CVE-AAA (KEV), CVE-BBB; host-b 10.0.0.6:443 ->
    CVE-AAA (KEV), CVE-CCC. Mirrors test_vex's _seed so suppression semantics
    line up across the surfaces."""
    conn = db.init_db(db_path)
    try:
        a = db.upsert_asset(conn, "10.0.0.5", "host-a", "up")
        sa = db.upsert_service(
            conn, a, 80, "tcp", "http", "nginx", "1.18.0",
            "cpe:2.3:a:nginx:nginx:1.18.0",
        )
        db.upsert_finding(conn, sa, "CVE-AAA", "aaa", "9.8", epss_score=0.9, kev=1)
        db.upsert_finding(conn, sa, "CVE-BBB", "bbb", "5.0")
        b = db.upsert_asset(conn, "10.0.0.6", "host-b", "up")
        sb = db.upsert_service(conn, b, 443, "tcp", "https", "nginx", "1.18.0", None)
        db.upsert_finding(conn, sb, "CVE-AAA", "aaa", "9.8", epss_score=0.9, kev=1)
        db.upsert_finding(conn, sb, "CVE-CCC", "ccc", "7.0")
        conn.commit()
    finally:
        conn.close()


def _set_matched_at(db_path, cve_id, when):
    """Force every finding for a CVE to a fixed matched_at timestamp."""
    conn = db.require_initialised(db_path)
    try:
        conn.execute(
            "UPDATE findings SET matched_at = ? WHERE cve_id = ?", (when, cve_id)
        )
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------
# stats — VEX suppression excludes triaged findings from the counts
# --------------------------------------------------------------------------

def test_stats_no_vex_counts_everything(db_path):
    _seed(db_path)
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn)
    finally:
        conn.close()
    assert summary["findings"] == 4
    assert summary["kev"] == 2


def test_stats_blanket_vex_drops_cve_from_counts(db_path):
    _seed(db_path)
    s = vex.parse(_vex_doc(_statement("CVE-AAA", "not_affected")))
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn, vex=s)
    finally:
        conn.close()
    # Both CVE-AAA findings (the two KEV hits) drop -> 2 findings, 0 KEV left.
    assert summary["findings"] == 2
    assert summary["kev"] == 0
    cves_left = {f["cve_id"] for f in summary["top_findings"]}
    assert cves_left == {"CVE-BBB", "CVE-CCC"}


def test_stats_scoped_vex_drops_cve_on_one_host_only(db_path):
    _seed(db_path)
    s = vex.parse(
        _vex_doc(_statement("CVE-AAA", "fixed", products=[{"@id": "10.0.0.5"}]))
    )
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn, vex=s)
    finally:
        conn.close()
    # CVE-AAA suppressed only on host-a; host-b keeps its KEV hit.
    assert summary["findings"] == 3
    assert summary["kev"] == 1


def test_stats_vex_composes_with_kev_only(db_path):
    _seed(db_path)
    s = vex.parse(_vex_doc(_statement("CVE-AAA", "not_affected")))
    conn = db.require_initialised(db_path)
    try:
        summary = stats.build_stats(conn, kev_only=True, vex=s)
    finally:
        conn.close()
    # kev_only keeps only the CVE-AAA hits; suppressing them leaves nothing.
    assert summary["findings"] == 0
    assert summary["assets"] == 0


def test_stats_text_header_records_vex_scope(db_path, tmp_path, capsys):
    _seed(db_path)
    path = _write(tmp_path, _vex_doc(_statement("CVE-AAA", "fixed")))
    out = stats.stats(db_path, "text", vex_path=path)
    assert "vex-suppressed" in out.splitlines()[0]


def test_cli_stats_vex_flag(db_path, tmp_path, capsys):
    _seed(db_path)
    path = _write(tmp_path, _vex_doc(_statement("CVE-AAA", "not_affected")))
    rc = cli.main(["stats", "--db", str(db_path), "--format", "json", "--vex", str(path)])
    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["findings"] == 2
    assert summary["kev"] == 0


def test_cli_stats_bad_vex_file_errors(db_path, tmp_path, capsys):
    _seed(db_path)
    rc = cli.main(["stats", "--db", str(db_path), "--vex", str(tmp_path / "nope.json")])
    assert rc == 1
    assert "VEX file not found" in capsys.readouterr().err


# --------------------------------------------------------------------------
# stale — a VEX-suppressed finding is never flagged stale
# --------------------------------------------------------------------------

# Fixed reference time so the age comparison is deterministic.
NOW = datetime(2026, 5, 29, 12, 0, 0, tzinfo=timezone.utc)


def test_stale_no_vex_flags_old_findings(db_path):
    _seed(db_path)
    _set_matched_at(db_path, "CVE-AAA", "2026-01-01 12:00:00")
    _set_matched_at(db_path, "CVE-BBB", "2026-01-01 12:00:00")
    _set_matched_at(db_path, "CVE-CCC", "2026-01-01 12:00:00")
    conn = db.require_initialised(db_path)
    try:
        report = stale.build_stale(conn, now=NOW)
    finally:
        conn.close()
    assert report["count"] == 4  # all four are old


def test_stale_vex_excludes_suppressed_finding(db_path):
    _seed(db_path)
    _set_matched_at(db_path, "CVE-AAA", "2026-01-01 12:00:00")
    _set_matched_at(db_path, "CVE-BBB", "2026-01-01 12:00:00")
    _set_matched_at(db_path, "CVE-CCC", "2026-01-01 12:00:00")
    s = vex.parse(_vex_doc(_statement("CVE-AAA", "fixed")))
    conn = db.require_initialised(db_path)
    try:
        report = stale.build_stale(conn, now=NOW, vex=s)
    finally:
        conn.close()
    # The two CVE-AAA rows are triage-cleared -> not flagged stale.
    assert report["count"] == 2
    flagged = {row["cve_id"] for row in report["stale"]}
    assert flagged == {"CVE-BBB", "CVE-CCC"}


def test_stale_text_header_records_vex_scope(db_path, tmp_path):
    _seed(db_path)
    path = _write(tmp_path, _vex_doc(_statement("CVE-AAA", "fixed")))
    out = stale.stale(db_path, "text", vex_path=path)
    assert "vex-suppressed" in out.splitlines()[0]


def test_cli_stale_vex_flag(db_path, tmp_path, capsys):
    _seed(db_path)
    _set_matched_at(db_path, "CVE-AAA", "2020-01-01 12:00:00")
    _set_matched_at(db_path, "CVE-BBB", "2020-01-01 12:00:00")
    _set_matched_at(db_path, "CVE-CCC", "2020-01-01 12:00:00")
    path = _write(tmp_path, _vex_doc(_statement("CVE-AAA", "not_affected")))
    rc = cli.main(
        ["stale", "--db", str(db_path), "--format", "json", "--vex", str(path)]
    )
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    flagged = {row["cve_id"] for row in report["stale"]}
    assert "CVE-AAA" not in flagged
    assert flagged == {"CVE-BBB", "CVE-CCC"}


def test_cli_stale_bad_vex_file_errors(db_path, tmp_path, capsys):
    _seed(db_path)
    rc = cli.main(["stale", "--db", str(db_path), "--vex", str(tmp_path / "nope.json")])
    assert rc == 1
    assert "VEX file not found" in capsys.readouterr().err


# --------------------------------------------------------------------------
# diff — VEX is applied to both sides before the comparison
# --------------------------------------------------------------------------

def _seed_pair(baseline_db, current_db):
    """Two DBs sharing host-a:80. Baseline has CVE-AAA + CVE-BBB; current has
    CVE-AAA + CVE-CCC. Without VEX: CVE-CCC new, CVE-BBB resolved, CVE-AAA
    persisting."""
    conn = db.init_db(baseline_db)
    try:
        a = db.upsert_asset(conn, "10.0.0.5", "host-a", "up")
        sa = db.upsert_service(conn, a, 80, "tcp", "http", "nginx", "1.18.0", None)
        db.upsert_finding(conn, sa, "CVE-AAA", "aaa", "9.8", epss_score=0.9, kev=1)
        db.upsert_finding(conn, sa, "CVE-BBB", "bbb", "5.0")
        conn.commit()
    finally:
        conn.close()

    conn = db.init_db(current_db)
    try:
        a = db.upsert_asset(conn, "10.0.0.5", "host-a", "up")
        sa = db.upsert_service(conn, a, 80, "tcp", "http", "nginx", "1.18.0", None)
        db.upsert_finding(conn, sa, "CVE-AAA", "aaa", "9.8", epss_score=0.9, kev=1)
        db.upsert_finding(conn, sa, "CVE-CCC", "ccc", "7.0")
        conn.commit()
    finally:
        conn.close()


def test_diff_no_vex_baseline(tmp_path):
    base = tmp_path / "base.db"
    cur = tmp_path / "cur.db"
    _seed_pair(base, cur)
    result = findingdiff.build_diff(base, cur)
    assert {e["cve_id"] for e in result["new"]} == {"CVE-CCC"}
    assert {e["cve_id"] for e in result["resolved"]} == {"CVE-BBB"}
    assert {e["cve_id"] for e in result["persisting"]} == {"CVE-AAA"}


def test_diff_vex_suppresses_persisting_on_both_sides(tmp_path):
    base = tmp_path / "base.db"
    cur = tmp_path / "cur.db"
    _seed_pair(base, cur)
    # CVE-AAA persists in both DBs; a blanket clearance hides it from both sides
    # so it no longer appears as persisting.
    s = vex.parse(_vex_doc(_statement("CVE-AAA", "not_affected")))
    result = findingdiff.build_diff(base, cur, vex=s)
    assert {e["cve_id"] for e in result["persisting"]} == set()
    # The other two are untouched by the ruling.
    assert {e["cve_id"] for e in result["new"]} == {"CVE-CCC"}
    assert {e["cve_id"] for e in result["resolved"]} == {"CVE-BBB"}


def test_cli_diff_vex_flag(tmp_path, capsys):
    base = tmp_path / "base.db"
    cur = tmp_path / "cur.db"
    _seed_pair(base, cur)
    path = _write(tmp_path, _vex_doc(_statement("CVE-AAA", "fixed")))
    rc = cli.main(
        [
            "diff",
            "--db", str(base),
            "--against", str(cur),
            "--format", "json",
            "--vex", str(path),
        ]
    )
    assert rc == 0
    result = json.loads(capsys.readouterr().out)
    assert {e["cve_id"] for e in result["persisting"]} == set()
    assert {e["cve_id"] for e in result["new"]} == {"CVE-CCC"}
    assert {e["cve_id"] for e in result["resolved"]} == {"CVE-BBB"}


def test_cli_diff_bad_vex_file_errors(tmp_path, capsys):
    base = tmp_path / "base.db"
    cur = tmp_path / "cur.db"
    _seed_pair(base, cur)
    rc = cli.main(
        [
            "diff",
            "--db", str(base),
            "--against", str(cur),
            "--vex", str(tmp_path / "nope.json"),
        ]
    )
    assert rc == 1
    assert "VEX file not found" in capsys.readouterr().err
