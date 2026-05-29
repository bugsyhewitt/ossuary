"""Tests for the `ossuary web` read surface — the web-probe inventory listing.

`ossuary web` is the read companion to `ossuary probe`: it surfaces the
``web_probes`` rows `probe` persists. No network is touched here — rows are
written directly via the same ``probe.upsert_web_probe`` helper `probe` uses.
"""

from __future__ import annotations

import json

import pytest

from ossuary import cli, db, web as web_mod
from ossuary.probe import ProbeResult
from ossuary.web import _decode_json_list, build_web


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _seed_probe(
    conn,
    ip,
    port,
    *,
    hostname=None,
    protocol="https",
    status_code=200,
    server="nginx/1.24.0",
    title="Home",
    redirect_chain=None,
    techs=None,
):
    """Insert an asset (if new) and a web_probes row via the real upsert helper."""
    asset_id = db.upsert_asset(conn, ip, hostname, "up")
    from ossuary import probe as probe_mod

    result = ProbeResult(
        protocol=protocol,
        status_code=status_code,
        server=server,
        title=title,
        redirect_chain=redirect_chain or [],
        tech_fingerprints=techs or [],
    )
    probe_mod.upsert_web_probe(conn, asset_id, port, protocol, result)
    conn.commit()
    return asset_id


@pytest.fixture
def seeded_db(db_path):
    """An initialised DB with three web probes across two hosts."""
    conn = db.init_db(db_path)
    _seed_probe(
        conn,
        "10.0.0.1",
        443,
        hostname="alpha.example",
        status_code=200,
        server="nginx/1.24.0",
        title="Alpha",
        techs=["nginx", "wordpress"],
    )
    _seed_probe(
        conn,
        "10.0.0.1",
        80,
        hostname="alpha.example",
        protocol="http",
        status_code=301,
        server="nginx/1.24.0",
        title=None,
        redirect_chain=["https://alpha.example/"],
        techs=["nginx"],
    )
    _seed_probe(
        conn,
        "10.0.0.2",
        8443,
        status_code=200,
        server="Apache/2.4.51",
        title="Beta admin",
        techs=["apache", "php"],
    )
    conn.close()
    return db_path


# ---------------------------------------------------------------------------
# _decode_json_list helper
# ---------------------------------------------------------------------------

def test_decode_json_list_valid():
    assert _decode_json_list('["nginx", "php"]') == ["nginx", "php"]


def test_decode_json_list_none():
    assert _decode_json_list(None) == []


def test_decode_json_list_blank():
    assert _decode_json_list("") == []


def test_decode_json_list_bad_json():
    assert _decode_json_list("{not json") == []


def test_decode_json_list_non_list():
    # A JSON object (not a list) degrades to an empty list.
    assert _decode_json_list('{"a": 1}') == []


# ---------------------------------------------------------------------------
# build_web — core listing
# ---------------------------------------------------------------------------

def test_build_web_lists_all_probes(seeded_db):
    conn = db.connect(seeded_db)
    try:
        report = build_web(conn)
    finally:
        conn.close()
    assert report["count"] == 3
    assert len(report["probes"]) == 3


def test_build_web_orders_by_ip_then_port(seeded_db):
    conn = db.connect(seeded_db)
    try:
        report = build_web(conn)
    finally:
        conn.close()
    locs = [(p["ip"], p["port"]) for p in report["probes"]]
    assert locs == [("10.0.0.1", 80), ("10.0.0.1", 443), ("10.0.0.2", 8443)]


def test_build_web_decodes_tech_fingerprints(seeded_db):
    conn = db.connect(seeded_db)
    try:
        report = build_web(conn)
    finally:
        conn.close()
    by_loc = {(p["ip"], p["port"]): p for p in report["probes"]}
    assert by_loc[("10.0.0.1", 443)]["tech_fingerprints"] == ["nginx", "wordpress"]


def test_build_web_decodes_redirect_chain(seeded_db):
    conn = db.connect(seeded_db)
    try:
        report = build_web(conn)
    finally:
        conn.close()
    by_loc = {(p["ip"], p["port"]): p for p in report["probes"]}
    assert by_loc[("10.0.0.1", 80)]["redirect_chain"] == ["https://alpha.example/"]


def test_build_web_carries_hostname_and_status(seeded_db):
    conn = db.connect(seeded_db)
    try:
        report = build_web(conn)
    finally:
        conn.close()
    by_loc = {(p["ip"], p["port"]): p for p in report["probes"]}
    probe = by_loc[("10.0.0.1", 443)]
    assert probe["hostname"] == "alpha.example"
    assert probe["status_code"] == 200
    assert probe["server"] == "nginx/1.24.0"


def test_build_web_empty_db(db_path):
    conn = db.init_db(db_path)
    try:
        report = build_web(conn)
    finally:
        conn.close()
    assert report == {"count": 0, "probes": []}


# ---------------------------------------------------------------------------
# build_web — host filter
# ---------------------------------------------------------------------------

def test_build_web_host_filter_by_ip(seeded_db):
    conn = db.connect(seeded_db)
    try:
        report = build_web(conn, host="10.0.0.2")
    finally:
        conn.close()
    assert report["count"] == 1
    assert report["probes"][0]["ip"] == "10.0.0.2"


def test_build_web_host_filter_by_hostname(seeded_db):
    conn = db.connect(seeded_db)
    try:
        report = build_web(conn, host="alpha.example")
    finally:
        conn.close()
    assert report["count"] == 2
    assert all(p["ip"] == "10.0.0.1" for p in report["probes"])


def test_build_web_host_filter_no_match(seeded_db):
    conn = db.connect(seeded_db)
    try:
        report = build_web(conn, host="10.9.9.9")
    finally:
        conn.close()
    assert report["count"] == 0


# ---------------------------------------------------------------------------
# build_web — tech filter
# ---------------------------------------------------------------------------

def test_build_web_tech_filter_exact(seeded_db):
    conn = db.connect(seeded_db)
    try:
        report = build_web(conn, tech="wordpress")
    finally:
        conn.close()
    assert report["count"] == 1
    assert report["probes"][0]["port"] == 443


def test_build_web_tech_filter_case_insensitive(seeded_db):
    conn = db.connect(seeded_db)
    try:
        report = build_web(conn, tech="NGINX")
    finally:
        conn.close()
    # nginx appears on both 10.0.0.1 probes.
    assert report["count"] == 2


def test_build_web_tech_filter_substring(seeded_db):
    conn = db.connect(seeded_db)
    try:
        report = build_web(conn, tech="press")  # substring of "wordpress"
    finally:
        conn.close()
    assert report["count"] == 1


def test_build_web_host_and_tech_compose(seeded_db):
    conn = db.connect(seeded_db)
    try:
        report = build_web(conn, host="alpha.example", tech="wordpress")
    finally:
        conn.close()
    assert report["count"] == 1
    assert report["probes"][0]["ip"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# web() — JSON serialisation
# ---------------------------------------------------------------------------

def test_web_json_round_trips(seeded_db):
    out = web_mod.web(seeded_db, "json")
    parsed = json.loads(out)
    assert parsed["count"] == 3
    assert isinstance(parsed["probes"], list)
    # Structured columns are decoded lists, not raw JSON strings.
    assert all(isinstance(p["tech_fingerprints"], list) for p in parsed["probes"])


def test_web_json_empty(db_path):
    db.init_db(db_path).close()
    parsed = json.loads(web_mod.web(db_path, "json"))
    assert parsed == {"count": 0, "probes": []}


# ---------------------------------------------------------------------------
# web() — text serialisation
# ---------------------------------------------------------------------------

def test_web_text_lists_locations(seeded_db):
    out = web_mod.web(seeded_db, "text")
    assert "web inventory" in out
    assert "count: 3" in out
    assert "https://10.0.0.1:443" in out
    assert "http://10.0.0.1:80" in out
    assert "https://10.0.0.2:8443" in out


def test_web_text_shows_tech_and_title(seeded_db):
    out = web_mod.web(seeded_db, "text")
    assert "nginx, wordpress" in out
    assert "title: Alpha" in out


def test_web_text_shows_redirect_chain(seeded_db):
    out = web_mod.web(seeded_db, "text")
    assert "redirects: https://alpha.example/" in out


def test_web_text_empty_db_message(db_path):
    db.init_db(db_path).close()
    out = web_mod.web(db_path, "text")
    assert "none" in out
    assert "ossuary probe" in out


def test_web_text_scope_suffix_records_filters(seeded_db):
    out = web_mod.web(seeded_db, "text", host="alpha.example", tech="nginx")
    assert "host: alpha.example" in out
    assert "tech: nginx" in out


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_web_unsupported_format(seeded_db):
    with pytest.raises(ValueError, match="unsupported web format"):
        web_mod.web(seeded_db, "xml")


def test_web_uninitialised_db(tmp_path):
    missing = tmp_path / "nope.db"
    with pytest.raises(RuntimeError, match="not initialised"):
        web_mod.web(missing, "text")


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

def test_cli_web_text(seeded_db, capsys):
    rc = cli.main(["web", "--db", str(seeded_db)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "web inventory" in out
    assert "count: 3" in out


def test_cli_web_json(seeded_db, capsys):
    rc = cli.main(["web", "--db", str(seeded_db), "--format", "json"])
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["count"] == 3


def test_cli_web_host_filter(seeded_db, capsys):
    rc = cli.main(["web", "--db", str(seeded_db), "--host", "10.0.0.2"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "count: 1" in out
    assert "10.0.0.2" in out


def test_cli_web_tech_filter(seeded_db, capsys):
    rc = cli.main(["web", "--db", str(seeded_db), "--tech", "wordpress"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "count: 1" in out


def test_cli_web_uninitialised_db_errors(tmp_path, capsys):
    missing = tmp_path / "nope.db"
    rc = cli.main(["web", "--db", str(missing)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "not initialised" in err
