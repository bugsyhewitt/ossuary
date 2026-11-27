"""Tests for ossuary's core logic modules: db, discover, fingerprint, cruise.

Covers edge cases and significant code paths not already exercised by the
per-module unit tests (test_db.py, test_discover.py, test_fingerprint.py).
No live nmap or network calls — all external seams are monkeypatched.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from conftest import host_discovery_result, service_scan_result

from ossuary import cruise as cruise_mod
from ossuary import db, discover, fingerprint


# ---------------------------------------------------------------------------
# db module
# ---------------------------------------------------------------------------


def test_init_db_creates_all_expected_tables(tmp_path):
    conn = db.init_db(tmp_path / "eng.db")
    names = db.table_names(conn)
    conn.close()
    for t in db.EXPECTED_TABLES:
        assert t in names


def test_init_db_is_idempotent(tmp_path):
    p = tmp_path / "eng.db"
    db.init_db(p).close()
    # second init must not raise or drop tables
    conn = db.init_db(p)
    names = db.table_names(conn)
    conn.close()
    for t in db.EXPECTED_TABLES:
        assert t in names


def test_upsert_asset_insert_then_update(tmp_path):
    conn = db.init_db(tmp_path / "eng.db")
    aid = db.upsert_asset(conn, "10.0.0.1", "host-a", "up")
    assert isinstance(aid, int)
    # update hostname on second call — same id
    aid2 = db.upsert_asset(conn, "10.0.0.1", "host-b", "up")
    assert aid == aid2
    row = conn.execute("SELECT hostname FROM assets WHERE ip='10.0.0.1'").fetchone()
    assert row["hostname"] == "host-b"
    conn.close()


def test_upsert_asset_records_scan_profile(tmp_path):
    conn = db.init_db(tmp_path / "eng.db")
    db.upsert_asset(conn, "10.0.0.5", None, "up", scan_profile="stealth")
    row = conn.execute("SELECT scan_profile FROM assets WHERE ip='10.0.0.5'").fetchone()
    assert row["scan_profile"] == "stealth"
    conn.close()


def test_upsert_service_insert_and_update(tmp_path):
    conn = db.init_db(tmp_path / "eng.db")
    aid = db.upsert_asset(conn, "10.0.0.1", None, "up")
    sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
    # second upsert (version bump) returns same id
    sid2 = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.25.0", None)
    assert sid == sid2
    row = conn.execute("SELECT version FROM services WHERE id=?", (sid,)).fetchone()
    assert row["version"] == "1.25.0"
    conn.close()


def test_upsert_finding_insert_and_update_severity(tmp_path):
    conn = db.init_db(tmp_path / "eng.db")
    aid = db.upsert_asset(conn, "10.0.0.1", None, "up")
    sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
    fid = db.upsert_finding(conn, sid, "CVE-2021-23017", "first", "7.5")
    fid2 = db.upsert_finding(conn, sid, "CVE-2021-23017", "updated", "9.8")
    assert fid == fid2
    row = conn.execute("SELECT severity FROM findings WHERE id=?", (fid,)).fetchone()
    assert row["severity"] == "9.8"
    conn.close()


def test_cascade_delete_removes_services_and_findings(tmp_path):
    conn = db.init_db(tmp_path / "eng.db")
    aid = db.upsert_asset(conn, "10.0.0.1", None, "up")
    sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
    db.upsert_finding(conn, sid, "CVE-X", "x", "7.0")
    conn.commit()
    conn.execute("DELETE FROM assets WHERE id=?", (aid,))
    conn.commit()
    svc_count = conn.execute("SELECT COUNT(*) FROM services").fetchone()[0]
    finding_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    assert svc_count == 0
    assert finding_count == 0
    conn.close()


def test_is_initialised_false_for_nonexistent_path(tmp_path):
    assert not db.is_initialised(tmp_path / "nope.db")


def test_is_initialised_false_for_empty_file(tmp_path):
    p = tmp_path / "empty.db"
    p.write_bytes(b"")
    assert not db.is_initialised(p)


def test_is_initialised_true_after_init_db(tmp_path):
    p = tmp_path / "eng.db"
    db.init_db(p).close()
    assert db.is_initialised(p)


def test_require_initialised_raises_on_missing(tmp_path):
    with pytest.raises(RuntimeError, match="not initialised"):
        db.require_initialised(tmp_path / "missing.db")


def test_require_initialised_raises_on_uninitialised_file(tmp_path):
    p = tmp_path / "empty.db"
    # write an empty sqlite file — tables don't exist
    sqlite3.connect(str(p)).close()
    with pytest.raises(RuntimeError, match="not initialised"):
        db.require_initialised(p)


def test_upsert_finding_stores_enrichment_fields(tmp_path):
    conn = db.init_db(tmp_path / "eng.db")
    aid = db.upsert_asset(conn, "10.0.0.1", None, "up")
    sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
    db.upsert_finding(conn, sid, "CVE-X", "x", "7.0", epss_score=0.85, kev=1, exploit=1)
    row = conn.execute("SELECT epss_score, kev, exploit FROM findings").fetchone()
    assert row["epss_score"] == 0.85
    assert row["kev"] == 1
    assert row["exploit"] == 1
    conn.close()


# ---------------------------------------------------------------------------
# discover module
# ---------------------------------------------------------------------------


def test_read_targets_ignores_comments_and_blanks(tmp_path):
    tfile = tmp_path / "targets.txt"
    tfile.write_text("# comment\n\n10.0.0.1\n192.168.0.0/24\n")
    result = discover.read_targets(tfile)
    assert result == ["10.0.0.1", "192.168.0.0/24"]


def test_read_targets_empty_file_returns_empty_list(tmp_path):
    tfile = tmp_path / "targets.txt"
    tfile.write_text("")
    assert discover.read_targets(tfile) == []


def test_read_targets_all_comments_returns_empty(tmp_path):
    tfile = tmp_path / "targets.txt"
    tfile.write_text("# only comments\n# another\n")
    assert discover.read_targets(tfile) == []


def test_discover_records_profile_on_asset(tmp_path, monkeypatch):
    db_path = tmp_path / "eng.db"
    tfile = tmp_path / "targets.txt"
    tfile.write_text("10.0.0.5\n")
    db.init_db(db_path).close()

    monkeypatch.setattr(
        discover, "scan_hosts",
        lambda targets, arguments="-sn": host_discovery_result(up_ips=["10.0.0.5"]),
    )
    discover.discover(db_path, tfile, profile="stealth")

    conn = db.connect(db_path)
    row = conn.execute("SELECT scan_profile FROM assets WHERE ip='10.0.0.5'").fetchone()
    conn.close()
    assert row["scan_profile"] == "stealth"


def test_discover_returns_zero_for_empty_targets(tmp_path, monkeypatch):
    db_path = tmp_path / "eng.db"
    tfile = tmp_path / "targets.txt"
    tfile.write_text("")
    db.init_db(db_path).close()
    count = discover.discover(db_path, tfile)
    assert count == 0


# ---------------------------------------------------------------------------
# fingerprint module
# ---------------------------------------------------------------------------


def test_fingerprint_clears_stale_services(tmp_path, monkeypatch):
    """Re-fingerprinting replaces old services rather than accumulating them."""
    db_path = tmp_path / "eng.db"
    tfile = tmp_path / "targets.txt"
    tfile.write_text("10.0.0.5\n")
    db.init_db(db_path).close()

    monkeypatch.setattr(
        discover, "scan_hosts",
        lambda targets, arguments="-sn": host_discovery_result(up_ips=["10.0.0.5"]),
    )
    discover.discover(db_path, tfile)

    # First scan — port 80 open
    monkeypatch.setattr(
        fingerprint, "scan_services",
        lambda ip, arguments="-sV": service_scan_result(
            ip, [{"port": 80, "name": "http", "product": "nginx", "version": "1.18.0"}]
        ),
    )
    fingerprint.fingerprint(db_path)

    # Second scan — port 80 gone, port 443 opens
    monkeypatch.setattr(
        fingerprint, "scan_services",
        lambda ip, arguments="-sV": service_scan_result(
            ip, [{"port": 443, "name": "https", "product": "nginx", "version": "1.25.0"}]
        ),
    )
    fingerprint.fingerprint(db_path)

    conn = db.connect(db_path)
    ports = [r["port"] for r in conn.execute("SELECT port FROM services").fetchall()]
    conn.close()
    assert ports == [443]  # port 80 must be gone


def test_fingerprint_records_scan_profile(tmp_path, monkeypatch):
    db_path = tmp_path / "eng.db"
    tfile = tmp_path / "targets.txt"
    tfile.write_text("10.0.0.5\n")
    db.init_db(db_path).close()

    monkeypatch.setattr(
        discover, "scan_hosts",
        lambda targets, arguments="-sn": host_discovery_result(up_ips=["10.0.0.5"]),
    )
    discover.discover(db_path, tfile)

    monkeypatch.setattr(
        fingerprint, "scan_services",
        lambda ip, arguments="-sV": service_scan_result(
            ip, [{"port": 80, "name": "http", "product": "nginx", "version": "1.18.0"}]
        ),
    )
    fingerprint.fingerprint(db_path, profile="web")

    conn = db.connect(db_path)
    row = conn.execute("SELECT scan_profile FROM services WHERE port=80").fetchone()
    conn.close()
    assert row["scan_profile"] == "web"


# ---------------------------------------------------------------------------
# cruise module — diff logic (pure, no I/O)
# ---------------------------------------------------------------------------


def test_diff_snapshots_detects_added_service():
    prev = {}
    curr = {"10.0.0.5:tcp/80": {"name": "http", "product": "nginx", "version": "1.18.0", "scan_profile": "default"}}
    result = cruise_mod.diff_snapshots(prev, curr)
    assert len(result["added"]) == 1
    assert result["added"][0]["service"] == "10.0.0.5:tcp/80"
    assert result["removed"] == []
    assert result["changed"] == []


def test_diff_snapshots_detects_removed_service():
    prev = {"10.0.0.5:tcp/80": {"name": "http", "product": "nginx", "version": "1.18.0", "scan_profile": "default"}}
    curr = {}
    result = cruise_mod.diff_snapshots(prev, curr)
    assert result["removed"][0]["service"] == "10.0.0.5:tcp/80"
    assert result["added"] == []


def test_diff_snapshots_detects_version_change():
    svc = {"name": "http", "product": "nginx", "version": "1.18.0", "scan_profile": "default"}
    prev = {"10.0.0.5:tcp/80": svc}
    curr = {"10.0.0.5:tcp/80": {**svc, "version": "1.25.0"}}
    result = cruise_mod.diff_snapshots(prev, curr)
    assert len(result["changed"]) == 1
    assert result["changed"][0]["from"]["version"] == "1.18.0"
    assert result["changed"][0]["to"]["version"] == "1.25.0"


def test_diff_snapshots_no_change_returns_empty_lists():
    svc = {"name": "http", "product": "nginx", "version": "1.18.0", "scan_profile": "default"}
    snap = {"10.0.0.5:tcp/80": svc}
    result = cruise_mod.diff_snapshots(snap, snap)
    assert result["added"] == []
    assert result["removed"] == []
    assert result["changed"] == []


def test_diff_tags_reports_added_and_removed():
    prev = {"10.0.0.5": ["in-scope"]}
    curr = {"10.0.0.5": ["in-scope", "vip"], "10.0.0.6": ["noise"]}
    changes = cruise_mod.diff_tags(prev, curr)
    # 10.0.0.5 gained "vip", 10.0.0.6 is entirely new
    asset_map = {c["asset"]: c for c in changes}
    assert "vip" in asset_map["10.0.0.5"]["added"]
    assert "noise" in asset_map["10.0.0.6"]["added"]


def test_diff_tags_no_change_returns_empty():
    snap = {"10.0.0.5": ["in-scope"]}
    assert cruise_mod.diff_tags(snap, snap) == []


def test_snapshot_services_key_format(tmp_path):
    conn = db.init_db(tmp_path / "eng.db")
    aid = db.upsert_asset(conn, "10.0.0.5", None, "up")
    db.upsert_service(conn, aid, 443, "tcp", "https", "nginx", "1.25.0", None)
    conn.commit()
    snap = cruise_mod.snapshot_services(conn)
    conn.close()
    assert "10.0.0.5:tcp/443" in snap
    assert snap["10.0.0.5:tcp/443"]["product"] == "nginx"
