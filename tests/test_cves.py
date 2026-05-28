"""Tests for CVE matching (criterion 6). OSV.dev + NVD HTTP are mocked."""

from __future__ import annotations

import sqlite3

from conftest import nvd_response, osv_response

from ossuary import cves, db


def _seed_service(db_path, product, version, cpe=None):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", None, "up")
        db.upsert_service(conn, aid, 80, "tcp", "http", product, version, cpe)
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

    # This test exercises OSV matching only; enrichment is covered in
    # test_enrich.py, so disable it here to keep the test offline.
    count = cves.match_cves(db_path, enrich_findings=False)
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


# --------------------------------------------------------------------------
# CPE extraction
# --------------------------------------------------------------------------

def test_extract_cpe_product_from_cpe23():
    cpe = "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    assert cves.extract_cpe_product(cpe) == "nginx"


def test_extract_cpe_product_distinct_vendor_and_product():
    cpe = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert cves.extract_cpe_product(cpe) == "http_server"


def test_extract_cpe_product_returns_none_for_unusable():
    assert cves.extract_cpe_product(None) is None
    assert cves.extract_cpe_product("") is None
    # not CPE 2.3
    assert cves.extract_cpe_product("cpe:/a:nginx:nginx") is None
    # ANY product is treated as absent
    assert cves.extract_cpe_product("cpe:2.3:a:vendor:*:*:*:*:*:*:*:*:*") is None


def test_resolve_product_prefers_cpe_then_falls_back():
    cpe = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    # CPE product (http_server) is more precise than the nmap name (Apache httpd)
    assert cves.resolve_product("Apache httpd", cpe) == "http_server"
    # no CPE => fall back to the nmap product name
    assert cves.resolve_product("Apache httpd", None) == "Apache httpd"


def test_match_cves_uses_cpe_derived_product_for_osv(db_path, monkeypatch):
    _seed_service(
        db_path,
        "Apache httpd",
        "2.4.49",
        cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
    )

    seen = {}

    def fake_query_osv(product, version):
        seen["product"] = product
        return osv_response([])

    monkeypatch.setattr(cves, "query_osv", fake_query_osv)
    cves.match_cves(db_path, enrich_findings=False)
    # The CPE product (http_server), not the raw nmap "Apache httpd", is queried.
    assert seen["product"] == "http_server"


# --------------------------------------------------------------------------
# NVD parsing + source selection
# --------------------------------------------------------------------------

def test_parse_nvd_response_extracts_id_summary_severity():
    resp = nvd_response(
        [
            {
                "id": "CVE-2021-41773",
                "summary": "Apache path traversal",
                "base_score": 7.5,
            }
        ]
    )
    findings = cves.parse_nvd_response(resp)
    assert len(findings) == 1
    assert findings[0]["cve_id"] == "CVE-2021-41773"
    assert findings[0]["summary"] == "Apache path traversal"
    assert findings[0]["severity"] == "7.5"


def test_parse_nvd_response_empty():
    assert cves.parse_nvd_response(nvd_response([])) == []
    assert cves.parse_nvd_response({}) == []


def test_nvd_not_called_for_default_osv_source(db_path, monkeypatch):
    _seed_service(db_path, "nginx", "1.18.0")
    monkeypatch.setattr(cves, "query_osv", lambda p, v: osv_response([]))

    nvd_called = False

    def fake_query_nvd(cpe, product, api_key=None):  # pragma: no cover
        nonlocal nvd_called
        nvd_called = True
        return nvd_response([])

    monkeypatch.setattr(cves, "query_nvd", fake_query_nvd)
    cves.match_cves(db_path, enrich_findings=False, source="osv")
    assert nvd_called is False


def test_nvd_called_when_source_nvd(db_path, monkeypatch):
    _seed_service(
        db_path,
        "nginx",
        "1.18.0",
        cpe="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
    )
    # OSV must NOT run when source is nvd-only.
    monkeypatch.setattr(
        cves,
        "query_osv",
        lambda p, v: (_ for _ in ()).throw(AssertionError("OSV should not run")),
    )
    seen = {}

    def fake_query_nvd(cpe, product, api_key=None):
        seen["cpe"] = cpe
        seen["product"] = product
        return nvd_response(
            [{"id": "CVE-2021-23017", "summary": "nginx bug", "base_score": 7.7}]
        )

    monkeypatch.setattr(cves, "query_nvd", fake_query_nvd)
    monkeypatch.setattr(cves.time, "sleep", lambda _s: None)

    count = cves.match_cves(db_path, enrich_findings=False, source="nvd")
    assert count == 1
    assert seen["cpe"] == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT cve_id, source FROM findings").fetchone()
    finally:
        conn.close()
    assert row["cve_id"] == "CVE-2021-23017"
    assert row["source"] == "nvd"


def test_both_sources_deduplicate_same_cve(db_path, monkeypatch):
    _seed_service(
        db_path,
        "nginx",
        "1.18.0",
        cpe="cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
    )

    def fake_query_osv(product, version):
        return osv_response(
            [
                {
                    "id": "GHSA-xxxx",
                    "aliases": ["CVE-2021-23017"],
                    "summary": "nginx resolver off-by-one",
                    "severity": [{"type": "CVSS_V3", "score": "7.7"}],
                }
            ]
        )

    def fake_query_nvd(cpe, product, api_key=None):
        # Same CVE id from NVD plus a second, NVD-only CVE.
        return nvd_response(
            [
                {"id": "CVE-2021-23017", "summary": "dup", "base_score": 7.7},
                {"id": "CVE-2019-9511", "summary": "HTTP/2 flood", "base_score": 7.5},
            ]
        )

    monkeypatch.setattr(cves, "query_osv", fake_query_osv)
    monkeypatch.setattr(cves, "query_nvd", fake_query_nvd)
    monkeypatch.setattr(cves.time, "sleep", lambda _s: None)

    count = cves.match_cves(db_path, enrich_findings=False, source="both")
    # 3 raw results across sources collapse to 2 unique CVE ids.
    assert count == 2

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        ids = {r["cve_id"] for r in conn.execute("SELECT cve_id FROM findings")}
    finally:
        conn.close()
    assert ids == {"CVE-2021-23017", "CVE-2019-9511"}


def test_nvd_rate_limit_sleep_invoked(db_path, monkeypatch):
    _seed_service(db_path, "nginx", "1.18.0")
    monkeypatch.setattr(
        cves, "query_nvd", lambda cpe, product, api_key=None: nvd_response([])
    )

    sleeps: list[float] = []
    monkeypatch.setattr(cves.time, "sleep", lambda s: sleeps.append(s))

    # No API key => the unauthenticated 0.6s spacing must be used.
    cves.match_cves(db_path, enrich_findings=False, source="nvd")
    assert sleeps == [cves.NVD_SLEEP_NO_KEY]


def test_nvd_api_key_shortens_rate_limit_sleep(db_path, monkeypatch):
    _seed_service(db_path, "nginx", "1.18.0")
    captured = {}

    def fake_query_nvd(cpe, product, api_key=None):
        captured["api_key"] = api_key
        return nvd_response([])

    monkeypatch.setattr(cves, "query_nvd", fake_query_nvd)
    sleeps: list[float] = []
    monkeypatch.setattr(cves.time, "sleep", lambda s: sleeps.append(s))

    cves.match_cves(
        db_path, enrich_findings=False, source="nvd", nvd_api_key="secret"
    )
    assert captured["api_key"] == "secret"
    assert sleeps == [cves.NVD_SLEEP_WITH_KEY]


def test_match_cves_rejects_unknown_source(db_path):
    _seed_service(db_path, "nginx", "1.18.0")
    try:
        cves.match_cves(db_path, source="bogus")
    except ValueError as exc:
        assert "bogus" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for unknown source")


# --------------------------------------------------------------------------
# Web-probe tech-fingerprint CVE matching (match_web_cves)
# --------------------------------------------------------------------------

def _seed_web_probe(db_path, server, port=443, ip="10.10.0.5"):
    """Init db, add an asset + its TCP service + a web_probes row, return ids."""
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, ip, None, "up")
        sid = db.upsert_service(conn, aid, port, "tcp", "http", None, None, None)
        conn.execute(
            "INSERT INTO web_probes (asset_id, port, protocol, status_code, "
            "server, tech_fingerprints) VALUES (?, ?, 'https', 200, ?, '[]')",
            (aid, port, server),
        )
        conn.commit()
        return aid, sid
    finally:
        conn.close()


def test_match_web_cves_matches_versioned_server_banner(db_path, monkeypatch):
    _aid, sid = _seed_web_probe(db_path, "nginx/1.24.0")

    seen = {}

    def fake_query(product, version):
        seen["product"] = product
        seen["version"] = version
        return osv_response(
            [
                {
                    "id": "GHSA-xxxx",
                    "aliases": ["CVE-2024-7347"],
                    "summary": "nginx mp4 module bug",
                    "severity": [{"type": "CVSS_V3", "score": "5.7"}],
                }
            ]
        )

    monkeypatch.setattr(cves, "query_osv", fake_query)
    count = cves.match_web_cves(db_path, enrich_findings=False)

    assert count == 1
    assert seen == {"product": "nginx", "version": "1.24.0"}

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT cve_id, service_id FROM findings").fetchone()
    finally:
        conn.close()
    # The finding attaches to the owning TCP service row (no orphan, no new table).
    assert row["cve_id"] == "CVE-2024-7347"
    assert row["service_id"] == sid


def test_match_web_cves_skips_versionless_banner(db_path, monkeypatch):
    _seed_web_probe(db_path, "cloudflare")

    called = False

    def fake_query(product, version):  # pragma: no cover - must not run
        nonlocal called
        called = True
        return osv_response([])

    monkeypatch.setattr(cves, "query_osv", fake_query)
    count = cves.match_web_cves(db_path, enrich_findings=False)
    assert count == 0
    assert called is False


def test_match_web_cves_skips_unknown_product(db_path, monkeypatch):
    _seed_web_probe(db_path, "SomeRandomServer/9.9.9")
    monkeypatch.setattr(
        cves,
        "query_osv",
        lambda p, v: (_ for _ in ()).throw(AssertionError("should not query")),
    )
    assert cves.match_web_cves(db_path, enrich_findings=False) == 0


def test_match_web_cves_apache_uses_http_server_product(db_path, monkeypatch):
    _seed_web_probe(db_path, "Apache/2.4.51 (Ubuntu)", port=80)
    seen = {}

    def fake_query(product, version):
        seen["product"] = product
        return osv_response([])

    monkeypatch.setattr(cves, "query_osv", fake_query)
    cves.match_web_cves(db_path, enrich_findings=False)
    assert seen["product"] == "http_server"


def test_match_web_cves_nvd_source(db_path, monkeypatch):
    _seed_web_probe(db_path, "nginx/1.24.0")
    monkeypatch.setattr(
        cves,
        "query_osv",
        lambda p, v: (_ for _ in ()).throw(AssertionError("OSV should not run")),
    )

    def fake_query_nvd(cpe, product, api_key=None):
        # Web banners carry no CPE; NVD must be queried by keywordSearch.
        assert cpe is None
        assert product == "nginx"
        return nvd_response(
            [{"id": "CVE-2024-7347", "summary": "nginx bug", "base_score": 5.7}]
        )

    monkeypatch.setattr(cves, "query_nvd", fake_query_nvd)
    monkeypatch.setattr(cves.time, "sleep", lambda _s: None)

    count = cves.match_web_cves(db_path, enrich_findings=False, source="nvd")
    assert count == 1

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT cve_id, source FROM findings").fetchone()
    finally:
        conn.close()
    assert row["cve_id"] == "CVE-2024-7347"
    assert row["source"] == "nvd"


def test_match_web_cves_rejects_unknown_source(db_path):
    _seed_web_probe(db_path, "nginx/1.24.0")
    try:
        cves.match_web_cves(db_path, source="bogus")
    except ValueError as exc:
        assert "bogus" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for unknown source")


def test_match_web_cves_no_probes_returns_zero(db_path, monkeypatch):
    db.init_db(db_path).close()
    monkeypatch.setattr(
        cves,
        "query_osv",
        lambda p, v: (_ for _ in ()).throw(AssertionError("should not query")),
    )
    assert cves.match_web_cves(db_path, enrich_findings=False) == 0


def test_match_web_cves_findings_surface_in_dump(db_path, monkeypatch):
    """A web-derived finding flows through dump like any service finding."""
    from ossuary import dump as dump_mod

    _seed_web_probe(db_path, "nginx/1.24.0", port=443)
    monkeypatch.setattr(
        cves,
        "query_osv",
        lambda p, v: osv_response(
            [{"id": "x", "aliases": ["CVE-2024-7347"], "summary": "bug"}]
        ),
    )
    cves.match_web_cves(db_path, enrich_findings=False)

    import json as _json

    state = _json.loads(dump_mod.dump(db_path))
    findings = state["assets"][0]["services"][0]["findings"]
    assert any(f["cve_id"] == "CVE-2024-7347" for f in findings)
