"""Tests for CVE matching (criterion 6). OSV.dev HTTP is mocked."""

from __future__ import annotations

import sqlite3

from conftest import osv_response

from ossuary import cves, db


def _seed_service(db_path, product, version):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", None, "up")
        db.upsert_service(conn, aid, 80, "tcp", "http", product, version, None)
        conn.commit()
    finally:
        conn.close()


def test_parse_osv_response_prefers_cve_alias():
    resp = osv_response(
        [
            {
                "id": "GHSA-xxxx",
                "aliases": ["CVE-2021-23017"],
                "summary": "nginx resolver off-by-one",
                "severity": [{"type": "CVSS_V3", "score": "7.7"}],
            }
        ]
    )
    findings = cves.parse_osv_response(resp)
    assert len(findings) == 1
    assert findings[0]["cve_id"] == "CVE-2021-23017"
    assert findings[0]["severity"] == "7.7"


def test_parse_osv_response_empty_when_no_vulns():
    assert cves.parse_osv_response(osv_response([])) == []
    assert cves.parse_osv_response({}) == []


def test_match_cves_populates_findings(db_path, monkeypatch):
    _seed_service(db_path, "nginx", "1.18.0")

    def fake_query(product, version):
        assert product == "nginx"
        assert version == "1.18.0"
        return osv_response(
            [
                {
                    "id": "GHSA-xxxx",
                    "aliases": ["CVE-2021-23017"],
                    "summary": "nginx resolver off-by-one heap write",
                    "severity": [{"type": "CVSS_V3", "score": "7.7"}],
                }
            ]
        )

    monkeypatch.setattr(cves, "query_osv", fake_query)

    count = cves.match_cves(db_path)
    assert count == 1

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT cve_id, severity FROM findings").fetchone()
    finally:
        conn.close()
    assert row["cve_id"] == "CVE-2021-23017"
    assert row["severity"] == "7.7"


def test_match_cves_skips_services_without_version(db_path, monkeypatch):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", None, "up")
        # no product/version => must be skipped
        db.upsert_service(conn, aid, 22, "tcp", "ssh", None, None, None)
        conn.commit()
    finally:
        conn.close()

    called = False

    def fake_query(product, version):  # pragma: no cover - must not run
        nonlocal called
        called = True
        return osv_response([])

    monkeypatch.setattr(cves, "query_osv", fake_query)
    count = cves.match_cves(db_path)
    assert count == 0
    assert called is False
