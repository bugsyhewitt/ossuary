"""Tests for cruise mode (criterion 8).

Two simulated state snapshots driven by a mocked nmap, confirming the diff
layer identifies added / removed / changed services. No scheduler involved —
single-invocation diff only.
"""

from __future__ import annotations

import sqlite3

from conftest import service_scan_result

from ossuary import cruise, db, fingerprint


def _seed_assets(db_path, ips):
    conn = db.init_db(db_path)
    try:
        for ip in ips:
            db.upsert_asset(conn, ip, None, "up")
        conn.commit()
    finally:
        conn.close()


def test_diff_snapshots_detects_added_removed_changed():
    prev = {
        "10.10.0.5:tcp/22": {"name": "ssh", "product": "OpenSSH", "version": "8.9p1"},
        "10.10.0.5:tcp/80": {"name": "http", "product": "nginx", "version": "1.18.0"},
    }
    cur = {
        # 22 removed
        "10.10.0.5:tcp/80": {"name": "http", "product": "nginx", "version": "1.25.0"},  # changed
        "10.10.0.5:tcp/443": {"name": "https", "product": "nginx", "version": "1.25.0"},  # added
    }
    diff = cruise.diff_snapshots(prev, cur)

    assert [a["service"] for a in diff["added"]] == ["10.10.0.5:tcp/443"]
    assert [r["service"] for r in diff["removed"]] == ["10.10.0.5:tcp/22"]
    assert len(diff["changed"]) == 1
    changed = diff["changed"][0]
    assert changed["service"] == "10.10.0.5:tcp/80"
    assert changed["from"]["version"] == "1.18.0"
    assert changed["to"]["version"] == "1.25.0"


def test_first_cruise_treats_everything_as_added(db_path, monkeypatch):
    _seed_assets(db_path, ["10.10.0.5"])
    monkeypatch.setattr(
        fingerprint,
        "scan_services",
        lambda ip: service_scan_result(
            ip, [{"port": 22, "name": "ssh", "product": "OpenSSH", "version": "8.9p1"}]
        ),
    )
    diff = cruise.cruise(db_path)
    assert len(diff["added"]) == 1
    assert diff["removed"] == []
    assert diff["changed"] == []

    # one cruise_runs row persisted
    conn = sqlite3.connect(str(db_path))
    try:
        n = conn.execute("SELECT COUNT(*) FROM cruise_runs").fetchone()[0]
    finally:
        conn.close()
    assert n == 1


def test_second_cruise_diffs_against_first(db_path, monkeypatch):
    _seed_assets(db_path, ["10.10.0.5"])

    # State snapshot 1: ssh 8.9p1 + http nginx 1.18.0
    snapshot_one = service_scan_result(
        "10.10.0.5",
        [
            {"port": 22, "name": "ssh", "product": "OpenSSH", "version": "8.9p1"},
            {"port": 80, "name": "http", "product": "nginx", "version": "1.18.0"},
        ],
    )
    # State snapshot 2: ssh gone, http nginx upgraded, https added
    snapshot_two = service_scan_result(
        "10.10.0.5",
        [
            {"port": 80, "name": "http", "product": "nginx", "version": "1.25.0"},
            {"port": 443, "name": "https", "product": "nginx", "version": "1.25.0"},
        ],
    )

    state = {"value": snapshot_one}
    monkeypatch.setattr(fingerprint, "scan_services", lambda ip: state["value"])

    first = cruise.cruise(db_path)
    assert len(first["added"]) == 2  # initial baseline

    # flip to snapshot two and cruise again
    state["value"] = snapshot_two
    second = cruise.cruise(db_path)

    added = {a["service"] for a in second["added"]}
    removed = {r["service"] for r in second["removed"]}
    changed = {c["service"] for c in second["changed"]}

    assert added == {"10.10.0.5:tcp/443"}
    assert removed == {"10.10.0.5:tcp/22"}
    assert changed == {"10.10.0.5:tcp/80"}

    # two cruise_runs rows now
    conn = sqlite3.connect(str(db_path))
    try:
        n = conn.execute("SELECT COUNT(*) FROM cruise_runs").fetchone()[0]
    finally:
        conn.close()
    assert n == 2
