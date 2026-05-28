"""Tests for the SQLite persistence layer (criterion 3: init creates tables)."""

from __future__ import annotations

import sqlite3

import pytest

from ossuary import db


def test_init_db_creates_all_expected_tables(db_path):
    conn = db.init_db(db_path)
    try:
        names = db.table_names(conn)
    finally:
        conn.close()
    assert set(db.EXPECTED_TABLES).issubset(names)
    assert {"assets", "services", "findings", "cruise_runs"}.issubset(names)


def test_init_db_is_idempotent(db_path):
    db.init_db(db_path).close()
    # second init must not raise or drop data
    db.init_db(db_path).close()
    assert db.is_initialised(db_path)


def test_is_initialised_false_for_missing_file(tmp_path):
    assert db.is_initialised(tmp_path / "nope.db") is False


def test_require_initialised_raises_on_uninitialised(tmp_path):
    with pytest.raises(RuntimeError, match="not initialised"):
        db.require_initialised(tmp_path / "nope.db")


def test_upsert_asset_dedupes_by_ip(db_path):
    conn = db.init_db(db_path)
    try:
        id1 = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        id2 = db.upsert_asset(conn, "10.10.0.5", "host-a-renamed", "up")
        conn.commit()
        assert id1 == id2
        row = conn.execute("SELECT hostname FROM assets WHERE ip='10.10.0.5'").fetchone()
        assert row["hostname"] == "host-a-renamed"
        count = conn.execute("SELECT COUNT(*) AS c FROM assets").fetchone()["c"]
        assert count == 1
    finally:
        conn.close()


def test_scan_profile_migration_adds_columns_to_legacy_db(tmp_path):
    """A pre-profile engagement DB (no scan_profile columns) gains them on the
    next init_db without losing existing rows, defaulting to 'default'."""
    path = tmp_path / "legacy.db"
    legacy = sqlite3.connect(str(path))
    legacy.executescript(
        """
        CREATE TABLE assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            hostname TEXT,
            state TEXT NOT NULL DEFAULT 'up',
            discovered_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL DEFAULT 'tcp',
            name TEXT, product TEXT, version TEXT, cpe TEXT,
            fingerprinted_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(asset_id, port, protocol)
        );
        CREATE TABLE findings (id INTEGER PRIMARY KEY, service_id INTEGER, cve_id TEXT);
        CREATE TABLE cruise_runs (id INTEGER PRIMARY KEY, snapshot TEXT NOT NULL DEFAULT '{}');
        """
    )
    legacy.execute("INSERT INTO assets (ip) VALUES ('10.10.0.5')")
    legacy.execute(
        "INSERT INTO services (asset_id, port) VALUES (1, 22)"
    )
    legacy.commit()
    legacy.close()

    # init_db runs the additive migration.
    db.init_db(path).close()

    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    try:
        asset = conn.execute("SELECT scan_profile FROM assets").fetchone()
        service = conn.execute("SELECT scan_profile FROM services").fetchone()
    finally:
        conn.close()
    assert asset["scan_profile"] == "default"
    assert service["scan_profile"] == "default"


def test_foreign_key_cascade_on_asset_delete(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", None, "up")
        sid = db.upsert_service(conn, aid, 22, "tcp", "ssh", "OpenSSH", "8.9", None)
        db.upsert_finding(conn, sid, "CVE-2020-0001", "x", "HIGH")
        conn.commit()
        conn.execute("DELETE FROM assets WHERE id = ?", (aid,))
        conn.commit()
        assert conn.execute("SELECT COUNT(*) AS c FROM services").fetchone()["c"] == 0
        assert conn.execute("SELECT COUNT(*) AS c FROM findings").fetchone()["c"] == 0
    finally:
        conn.close()
