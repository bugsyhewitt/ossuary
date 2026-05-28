"""Tests for service fingerprinting (criterion 5). Nmap output is mocked."""

from __future__ import annotations

import sqlite3

from conftest import service_scan_result

from ossuary import db, fingerprint


def _seed_assets(db_path, ips):
    conn = db.init_db(db_path)
    try:
        for ip in ips:
            db.upsert_asset(conn, ip, None, "up")
        conn.commit()
    finally:
        conn.close()


def test_parse_services_returns_open_ports_with_versions():
    result = service_scan_result(
        "10.10.0.5",
        [
            {"port": 22, "name": "ssh", "product": "OpenSSH", "version": "8.9p1"},
            {"port": 80, "name": "http", "product": "nginx", "version": "1.18.0"},
            {"port": 443, "name": "https", "product": "", "version": "", "state": "closed"},
        ],
    )
    svcs = fingerprint.parse_services("10.10.0.5", result)
    ports = {s["port"] for s in svcs}
    assert ports == {22, 80}  # closed port excluded
    ssh = next(s for s in svcs if s["port"] == 22)
    assert ssh["product"] == "OpenSSH"
    assert ssh["version"] == "8.9p1"


def test_fingerprint_populates_services_with_version_metadata(db_path, monkeypatch):
    _seed_assets(db_path, ["10.10.0.5"])

    def fake_scan_services(ip, arguments="-sV"):
        return service_scan_result(
            ip,
            [
                {"port": 22, "name": "ssh", "product": "OpenSSH", "version": "8.9p1"},
                {"port": 80, "name": "http", "product": "nginx", "version": "1.18.0"},
            ],
        )

    monkeypatch.setattr(fingerprint, "scan_services", fake_scan_services)

    count = fingerprint.fingerprint(db_path)
    assert count == 2

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT port, product, version FROM services ORDER BY port"
        ).fetchall()
    finally:
        conn.close()
    assert [(r["port"], r["product"], r["version"]) for r in rows] == [
        (22, "OpenSSH", "8.9p1"),
        (80, "nginx", "1.18.0"),
    ]


def test_fingerprint_does_not_duplicate_unchanged_service(db_path, monkeypatch):
    _seed_assets(db_path, ["10.10.0.5"])
    monkeypatch.setattr(
        fingerprint,
        "scan_services",
        lambda ip, arguments="-sV": service_scan_result(
            ip, [{"port": 22, "name": "ssh", "product": "OpenSSH", "version": "8.9p1"}]
        ),
    )
    fingerprint.fingerprint(db_path)
    fingerprint.fingerprint(db_path)

    conn = sqlite3.connect(str(db_path))
    try:
        count = conn.execute("SELECT COUNT(*) FROM services").fetchone()[0]
    finally:
        conn.close()
    assert count == 1  # rescan replaces, never duplicates


def test_fingerprint_drops_services_that_disappear(db_path, monkeypatch):
    """A port that closes between scans must be removed from `services` so the
    cruise diff can report it as removed."""
    _seed_assets(db_path, ["10.10.0.5"])

    state = {
        "value": service_scan_result(
            "10.10.0.5",
            [
                {"port": 22, "name": "ssh", "product": "OpenSSH", "version": "8.9p1"},
                {"port": 80, "name": "http", "product": "nginx", "version": "1.18.0"},
            ],
        )
    }
    monkeypatch.setattr(
        fingerprint, "scan_services", lambda ip, arguments="-sV": state["value"]
    )
    fingerprint.fingerprint(db_path)

    # second scan: port 22 gone
    state["value"] = service_scan_result(
        "10.10.0.5", [{"port": 80, "name": "http", "product": "nginx", "version": "1.18.0"}]
    )
    fingerprint.fingerprint(db_path)

    conn = sqlite3.connect(str(db_path))
    try:
        ports = [r[0] for r in conn.execute("SELECT port FROM services ORDER BY port").fetchall()]
    finally:
        conn.close()
    assert ports == [80]
