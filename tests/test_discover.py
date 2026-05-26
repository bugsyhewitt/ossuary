"""Tests for host discovery (criterion 4). Nmap shell-out is mocked."""

from __future__ import annotations

import sqlite3

from conftest import TARGETS_FILE, host_discovery_result

from ossuary import db, discover


def test_read_targets_skips_blanks_and_comments():
    targets = discover.read_targets(TARGETS_FILE)
    assert targets == ["10.10.0.5", "10.10.0.6", "10.10.0.7"]


def test_parse_hosts_only_returns_up_hosts():
    result = host_discovery_result(up_ips=["10.10.0.5", "10.10.0.6"], down_ips=["10.10.0.7"])
    hosts = discover.parse_hosts(result)
    ips = {h["ip"] for h in hosts}
    assert ips == {"10.10.0.5", "10.10.0.6"}


def test_discover_populates_assets_table(db_path, monkeypatch):
    db.init_db(db_path).close()

    # Mock the network seam: two of three targets are up.
    def fake_scan_hosts(targets):
        assert targets == ["10.10.0.5", "10.10.0.6", "10.10.0.7"]
        return host_discovery_result(
            up_ips=["10.10.0.5", "10.10.0.6"], down_ips=["10.10.0.7"]
        )

    monkeypatch.setattr(discover, "scan_hosts", fake_scan_hosts)

    count = discover.discover(db_path, TARGETS_FILE)
    assert count == 2

    # Verify via direct sqlite3 query (per criterion 4).
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute("SELECT ip FROM assets ORDER BY ip").fetchall()
    finally:
        conn.close()
    assert [r[0] for r in rows] == ["10.10.0.5", "10.10.0.6"]


def test_discover_requires_initialised_db(tmp_path, monkeypatch):
    monkeypatch.setattr(discover, "scan_hosts", lambda t: host_discovery_result(["10.10.0.5"]))
    import pytest

    with pytest.raises(RuntimeError, match="not initialised"):
        discover.discover(tmp_path / "missing.db", TARGETS_FILE)
