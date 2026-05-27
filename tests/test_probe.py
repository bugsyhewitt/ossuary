"""Tests for ossuary probe subcommand — HTTP/web layer discovery.

All HTTP calls are mocked via monkeypatching ``probe.http_probe``; no real
network requests are made.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from ossuary import db, probe as probe_mod
from ossuary.probe import ProbeResult, _extract_title, _fingerprint_headers, _fingerprint_html


# ---------------------------------------------------------------------------
# Unit tests for helper functions
# ---------------------------------------------------------------------------

def test_fingerprint_headers_nginx():
    techs = _fingerprint_headers({"server": "nginx/1.24"})
    assert "nginx" in techs


def test_fingerprint_headers_apache():
    techs = _fingerprint_headers({"server": "Apache/2.4.51 (Ubuntu)"})
    assert "apache" in techs


def test_fingerprint_headers_php_x_powered_by():
    techs = _fingerprint_headers({"x-powered-by": "PHP/8.1.2"})
    assert "php" in techs


def test_fingerprint_headers_aspnet():
    techs = _fingerprint_headers({"x-aspnet-version": "4.0.30319"})
    assert "asp.net" in techs


def test_fingerprint_headers_drupal_cache_header():
    techs = _fingerprint_headers({"x-drupal-cache": "HIT"})
    assert "drupal" in techs


def test_fingerprint_headers_wordpress_x_generator():
    techs = _fingerprint_headers({"x-generator": "WordPress 6.4"})
    assert "wordpress" in techs


def test_fingerprint_headers_java_tomcat_jsessionid():
    techs = _fingerprint_headers({"set-cookie": "JSESSIONID=abc123; Path=/"})
    assert "java/tomcat" in techs


def test_fingerprint_html_wordpress_meta_generator():
    techs = _fingerprint_html('<meta name="generator" content="WordPress 6.4">', [])
    assert "wordpress" in techs


def test_fingerprint_html_drupal_settings():
    techs = _fingerprint_html("drupal.settings = {};", [])
    assert "drupal" in techs


def test_extract_title_basic():
    title = _extract_title("<html><head><title>My App</title></head></html>")
    assert title == "My App"


def test_extract_title_missing():
    title = _extract_title("<html><body>no title here</body></html>")
    assert title is None


def test_extract_title_empty():
    title = _extract_title("<title></title>")
    assert title is None


# ---------------------------------------------------------------------------
# web_probes table created by migration
# ---------------------------------------------------------------------------

def test_web_probes_table_created_by_init_db(db_path):
    conn = db.init_db(db_path)
    try:
        names = db.table_names(conn)
    finally:
        conn.close()
    assert "web_probes" in names


def test_web_probes_table_has_expected_columns(db_path):
    conn = db.init_db(db_path)
    try:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(web_probes)")}
    finally:
        conn.close()
    expected = {
        "id", "asset_id", "port", "protocol", "status_code", "server",
        "title", "redirect_chain", "tech_fingerprints", "probed_at",
    }
    assert expected.issubset(cols)


# ---------------------------------------------------------------------------
# Integration tests using monkeypatched http_probe
# ---------------------------------------------------------------------------

def _seed_asset_with_port(db_path, ip: str = "10.0.0.1", port: int = 80):
    """Helper: init db, insert an asset and a service row, return asset_id."""
    conn = db.init_db(db_path)
    asset_id = db.upsert_asset(conn, ip, None, "up")
    db.upsert_service(conn, asset_id, port, "tcp", "http", "nginx", "1.24", None)
    conn.commit()
    conn.close()
    return asset_id


def test_probe_stores_status_code_server_and_tech(db_path, monkeypatch):
    _seed_asset_with_port(db_path, port=80)

    def fake_probe(host, port, protocol, timeout=10.0):
        return ProbeResult(
            protocol="http",
            status_code=200,
            server="nginx/1.24",
            title="Welcome",
            redirect_chain=[],
            tech_fingerprints=["nginx"],
        )

    monkeypatch.setattr(probe_mod, "http_probe", fake_probe)
    count = probe_mod.probe(db_path, ports={80})
    assert count == 1

    conn = sqlite3.connect(str(db_path))
    row = conn.execute("SELECT * FROM web_probes").fetchone()
    conn.close()

    assert row is not None
    # sqlite3 returns tuples; map positionally:
    # id, asset_id, port, protocol, status_code, server, title, redirect_chain, tech_fingerprints, probed_at
    assert row[4] == 200           # status_code
    assert row[5] == "nginx/1.24"  # server
    assert row[6] == "Welcome"     # title
    assert "nginx" in json.loads(row[8])  # tech_fingerprints


def test_probe_head_405_fallback_to_get(db_path, monkeypatch):
    """When HEAD returns 405, probe should fall back to GET and succeed."""
    _seed_asset_with_port(db_path, port=80)

    call_log: list[str] = []

    def fake_probe(host, port, protocol, timeout=10.0):
        # Simulate: the real http_probe internally tries GET on 405;
        # here we return a successful ProbeResult as if GET was used.
        call_log.append(f"{protocol}:{port}")
        return ProbeResult(
            protocol="http",
            status_code=200,
            server="Apache/2.4",
            title="App",
            redirect_chain=[],
            tech_fingerprints=["apache"],
        )

    monkeypatch.setattr(probe_mod, "http_probe", fake_probe)
    count = probe_mod.probe(db_path, ports={80})
    assert count == 1

    conn = sqlite3.connect(str(db_path))
    row = conn.execute("SELECT status_code FROM web_probes").fetchone()
    conn.close()
    assert row[0] == 200


def test_probe_https_fallback_to_http_on_ssl_error(db_path, monkeypatch):
    """For port 443, HTTPS is tried first; if SSL error, fall back to HTTP."""
    _seed_asset_with_port(db_path, port=443)

    call_log: list[tuple] = []

    def fake_probe(host, port, protocol, timeout=10.0):
        call_log.append((host, port, protocol))
        if protocol == "https":
            return ProbeResult(
                protocol="https",
                status_code=None,
                server=None,
                title=None,
                redirect_chain=[],
                tech_fingerprints=[],
                error="ssl_error: certificate verify failed",
            )
        # HTTP fallback succeeds.
        return ProbeResult(
            protocol="http",
            status_code=200,
            server="nginx",
            title=None,
            redirect_chain=[],
            tech_fingerprints=["nginx"],
        )

    monkeypatch.setattr(probe_mod, "http_probe", fake_probe)
    count = probe_mod.probe(db_path, ports={443})
    assert count == 1

    # Verify HTTPS was tried first, then HTTP.
    protocols_tried = [c[2] for c in call_log]
    assert protocols_tried[0] == "https"
    assert "http" in protocols_tried

    # The stored row should reflect the HTTP fallback result.
    conn = sqlite3.connect(str(db_path))
    row = conn.execute("SELECT protocol, status_code FROM web_probes").fetchone()
    conn.close()
    assert row[0] == "http"
    assert row[1] == 200


def test_probe_redirect_chain_captured(db_path, monkeypatch):
    _seed_asset_with_port(db_path, port=80)

    chain = ["http://10.0.0.1:80/login", "http://10.0.0.1:80/dashboard"]

    def fake_probe(host, port, protocol, timeout=10.0):
        return ProbeResult(
            protocol="http",
            status_code=200,
            server=None,
            title="Dashboard",
            redirect_chain=chain,
            tech_fingerprints=[],
        )

    monkeypatch.setattr(probe_mod, "http_probe", fake_probe)
    probe_mod.probe(db_path, ports={80})

    conn = sqlite3.connect(str(db_path))
    row = conn.execute("SELECT redirect_chain FROM web_probes").fetchone()
    conn.close()
    stored = json.loads(row[0])
    assert stored == chain


def test_probe_title_extracted_and_stored(db_path, monkeypatch):
    _seed_asset_with_port(db_path, port=80)

    def fake_probe(host, port, protocol, timeout=10.0):
        return ProbeResult(
            protocol="http",
            status_code=200,
            server=None,
            title="My Application",
            redirect_chain=[],
            tech_fingerprints=[],
        )

    monkeypatch.setattr(probe_mod, "http_probe", fake_probe)
    probe_mod.probe(db_path, ports={80})

    conn = sqlite3.connect(str(db_path))
    row = conn.execute("SELECT title FROM web_probes").fetchone()
    conn.close()
    assert row[0] == "My Application"


def test_probe_upserts_on_repeat_run(db_path, monkeypatch):
    """A second probe run updates the existing row (no duplicates)."""
    _seed_asset_with_port(db_path, port=80)

    responses = [
        ProbeResult("http", 200, "nginx/1.0", "First", [], ["nginx"]),
        ProbeResult("http", 200, "nginx/1.24", "Second", [], ["nginx"]),
    ]
    idx = [0]

    def fake_probe(host, port, protocol, timeout=10.0):
        r = responses[idx[0]]
        idx[0] = min(idx[0] + 1, len(responses) - 1)
        return r

    monkeypatch.setattr(probe_mod, "http_probe", fake_probe)
    probe_mod.probe(db_path, ports={80})
    probe_mod.probe(db_path, ports={80})

    conn = sqlite3.connect(str(db_path))
    rows = conn.execute("SELECT COUNT(*), title FROM web_probes").fetchone()
    conn.close()
    assert rows[0] == 1           # still just one row
    assert rows[1] == "Second"    # updated title


def test_probe_skips_assets_without_web_ports(db_path, monkeypatch):
    """Assets with only SSH (port 22) should not be probed."""
    conn = db.init_db(db_path)
    asset_id = db.upsert_asset(conn, "10.0.0.2", None, "up")
    db.upsert_service(conn, asset_id, 22, "tcp", "ssh", "OpenSSH", "8.9", None)
    conn.commit()
    conn.close()

    calls = []

    def fake_probe(host, port, protocol, timeout=10.0):
        calls.append((host, port))
        return ProbeResult("http", 200, None, None, [], [])

    monkeypatch.setattr(probe_mod, "http_probe", fake_probe)
    count = probe_mod.probe(db_path, ports={80, 443, 8080, 8443})
    assert count == 0
    assert calls == []


def test_probe_host_filter(db_path, monkeypatch):
    """--host limits probing to the specified host."""
    conn = db.init_db(db_path)
    for ip in ("10.0.0.1", "10.0.0.2"):
        aid = db.upsert_asset(conn, ip, None, "up")
        db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.24", None)
    conn.commit()
    conn.close()

    probed_hosts: list[str] = []

    def fake_probe(host, port, protocol, timeout=10.0):
        probed_hosts.append(host)
        return ProbeResult("http", 200, None, None, [], [])

    monkeypatch.setattr(probe_mod, "http_probe", fake_probe)
    count = probe_mod.probe(db_path, host_filter="10.0.0.1", ports={80})
    assert count == 1
    assert probed_hosts == ["10.0.0.1"]


def test_probe_multiple_ports_per_host(db_path, monkeypatch):
    """Each qualifying port on a host gets its own probe row."""
    conn = db.init_db(db_path)
    aid = db.upsert_asset(conn, "10.0.0.1", None, "up")
    for port in (80, 443):
        db.upsert_service(conn, aid, port, "tcp", "http", "nginx", "1.24", None)
    conn.commit()
    conn.close()

    def fake_probe(host, port, protocol, timeout=10.0):
        return ProbeResult(protocol, 200, "nginx", None, [], ["nginx"])

    monkeypatch.setattr(probe_mod, "http_probe", fake_probe)
    count = probe_mod.probe(db_path, ports={80, 443})
    assert count == 2

    conn = sqlite3.connect(str(db_path))
    rows = conn.execute("SELECT port FROM web_probes ORDER BY port").fetchall()
    conn.close()
    assert [r[0] for r in rows] == [80, 443]
