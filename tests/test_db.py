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
