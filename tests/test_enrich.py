"""Tests for EPSS + CISA KEV enrichment of findings.

EPSS (FIRST API) and the CISA KEV catalog are the two network seams here:

    enrich.query_epss(cve_id)  -> EPSS float in [0, 1] or None
    enrich.fetch_kev_catalog() -> raw KEV catalog dict

Both are monkeypatched in tests — no test touches the network. The KEV catalog
is cached in the DB with a 24h TTL so repeated runs don't re-download it.
"""

from __future__ import annotations

import sqlite3

from ossuary import cves, db, enrich


# --------------------------------------------------------------------------
# builders
# --------------------------------------------------------------------------

def epss_response(cve_id: str, score: float) -> dict:
    """Build a FIRST EPSS `/data/v1/epss` response for one CVE."""
    return {
        "status": "OK",
        "data": [{"cve": cve_id, "epss": str(score), "percentile": "0.5"}],
    }


def epss_empty_response() -> dict:
    """EPSS response shape when the CVE has no score."""
    return {"status": "OK", "data": []}


def kev_catalog(cve_ids: list[str]) -> dict:
    """Build a CISA KEV catalog with the given CVE ids present."""
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.05.26",
        "vulnerabilities": [{"cveID": c, "vendorProject": "x"} for c in cve_ids],
    }


def exploitdb_index(cve_ids: list[str]) -> str:
    """Build an Exploit-DB files_exploits.csv index referencing the given CVEs.

    Each row carries a `codes` cell that lists CVE ids (semicolon-separated),
    mimicking the real index where one exploit may target several CVEs and the
    cell may also carry non-CVE codes (OSVDB ids etc).
    """
    header = "id,file,description,date_published,author,type,platform,port,codes\n"
    rows = []
    for i, c in enumerate(cve_ids, start=1):
        rows.append(
            f"{i},exploits/x/{i}.txt,Exploit {i},2024-01-0{i},author,"
            f"remote,linux,0,{c};OSVDB-{i}\n"
        )
    return header + "".join(rows)


def _seed_service(db_path, product, version):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", None, "up")
        db.upsert_service(conn, aid, 80, "tcp", "http", product, version, None)
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------
# migration / schema
# --------------------------------------------------------------------------

def test_init_db_adds_enrichment_columns(db_path):
    conn = db.init_db(db_path)
    try:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(findings)")}
    finally:
        conn.close()
    assert "epss_score" in cols
    assert "kev" in cols


def test_migration_adds_columns_to_legacy_findings_table(db_path):
    """A DB created with the old (pre-enrichment) findings schema must gain the
    new columns on the next init_db without losing data."""
    conn = sqlite3.connect(str(db_path))
    conn.executescript(
        """
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_id INTEGER NOT NULL,
            cve_id TEXT NOT NULL,
            summary TEXT,
            severity TEXT,
            source TEXT NOT NULL DEFAULT 'osv.dev',
            matched_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(service_id, cve_id)
        );
        CREATE TABLE assets (id INTEGER PRIMARY KEY, ip TEXT);
        CREATE TABLE services (id INTEGER PRIMARY KEY);
        CREATE TABLE cruise_runs (id INTEGER PRIMARY KEY, snapshot TEXT);
        INSERT INTO findings (service_id, cve_id, summary, severity)
            VALUES (1, 'CVE-2020-0001', 'legacy', 'HIGH');
        """
    )
    conn.commit()
    conn.close()

    # re-open through init_db: migration should add the columns
    db.init_db(db_path).close()

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(findings)")}
        row = conn.execute(
            "SELECT cve_id, epss_score, kev FROM findings WHERE cve_id='CVE-2020-0001'"
        ).fetchone()
    finally:
        conn.close()
    assert "epss_score" in cols and "kev" in cols
    assert row["cve_id"] == "CVE-2020-0001"  # legacy row preserved
    assert row["epss_score"] is None
    assert row["kev"] == 0  # default applied


# --------------------------------------------------------------------------
# EPSS enrichment
# --------------------------------------------------------------------------

def test_match_cves_enriches_epss_score(db_path, monkeypatch):
    _seed_service(db_path, "nginx", "1.18.0")

    monkeypatch.setattr(
        cves,
        "query_osv",
        lambda product, version: {
            "vulns": [
                {"id": "GHSA-x", "aliases": ["CVE-2021-23017"], "summary": "x",
                 "severity": []}
            ]
        },
    )
    monkeypatch.setattr(
        enrich, "query_epss", lambda cve_id: 0.87 if cve_id == "CVE-2021-23017" else None
    )
    monkeypatch.setattr(enrich, "fetch_kev_catalog", lambda: kev_catalog([]))
    monkeypatch.setattr(enrich, "fetch_exploitdb_index", lambda: exploitdb_index([]))

    count = cves.match_cves(db_path, enrich_findings=True)
    assert count == 1

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT epss_score, kev FROM findings").fetchone()
    finally:
        conn.close()
    assert row["epss_score"] == 0.87
    assert row["kev"] == 0


def test_match_cves_marks_kev_when_cve_in_catalog(db_path, monkeypatch):
    _seed_service(db_path, "nginx", "1.18.0")

    monkeypatch.setattr(
        cves,
        "query_osv",
        lambda product, version: {
            "vulns": [
                {"id": "GHSA-x", "aliases": ["CVE-2021-23017"], "summary": "x",
                 "severity": []}
            ]
        },
    )
    monkeypatch.setattr(enrich, "query_epss", lambda cve_id: 0.5)
    monkeypatch.setattr(
        enrich, "fetch_kev_catalog", lambda: kev_catalog(["CVE-2021-23017"])
    )
    monkeypatch.setattr(enrich, "fetch_exploitdb_index", lambda: exploitdb_index([]))

    cves.match_cves(db_path, enrich_findings=True)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT kev FROM findings").fetchone()
    finally:
        conn.close()
    assert row["kev"] == 1


def test_match_cves_kev_zero_when_cve_absent(db_path, monkeypatch):
    _seed_service(db_path, "nginx", "1.18.0")

    monkeypatch.setattr(
        cves,
        "query_osv",
        lambda product, version: {
            "vulns": [
                {"id": "GHSA-x", "aliases": ["CVE-2021-23017"], "summary": "x",
                 "severity": []}
            ]
        },
    )
    monkeypatch.setattr(enrich, "query_epss", lambda cve_id: 0.5)
    monkeypatch.setattr(
        enrich, "fetch_kev_catalog", lambda: kev_catalog(["CVE-9999-0000"])
    )
    monkeypatch.setattr(enrich, "fetch_exploitdb_index", lambda: exploitdb_index([]))

    cves.match_cves(db_path, enrich_findings=True)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT kev FROM findings").fetchone()
    finally:
        conn.close()
    assert row["kev"] == 0


def test_match_cves_no_enrich_makes_no_http_calls(db_path, monkeypatch):
    _seed_service(db_path, "nginx", "1.18.0")

    monkeypatch.setattr(
        cves,
        "query_osv",
        lambda product, version: {
            "vulns": [
                {"id": "GHSA-x", "aliases": ["CVE-2021-23017"], "summary": "x",
                 "severity": []}
            ]
        },
    )

    def boom_epss(cve_id):  # pragma: no cover - must not be called
        raise AssertionError("query_epss must not be called when enrich is off")

    def boom_kev():  # pragma: no cover - must not be called
        raise AssertionError("fetch_kev_catalog must not be called when enrich is off")

    def boom_edb():  # pragma: no cover - must not be called
        raise AssertionError("fetch_exploitdb_index must not be called when enrich is off")

    monkeypatch.setattr(enrich, "query_epss", boom_epss)
    monkeypatch.setattr(enrich, "fetch_kev_catalog", boom_kev)
    monkeypatch.setattr(enrich, "fetch_exploitdb_index", boom_edb)

    count = cves.match_cves(db_path, enrich_findings=False)
    assert count == 1

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT epss_score, kev, exploit FROM findings").fetchone()
    finally:
        conn.close()
    assert row["epss_score"] is None
    assert row["kev"] == 0
    assert row["exploit"] == 0


# --------------------------------------------------------------------------
# KEV cache (TTL)
# --------------------------------------------------------------------------

def test_kev_catalog_is_cached_across_calls(db_path, monkeypatch):
    db.init_db(db_path).close()
    conn = db.connect(db_path)
    calls = {"n": 0}

    def counting_fetch():
        calls["n"] += 1
        return kev_catalog(["CVE-2021-23017"])

    monkeypatch.setattr(enrich, "fetch_kev_catalog", counting_fetch)

    try:
        ids1 = enrich.get_kev_ids(conn)
        ids2 = enrich.get_kev_ids(conn)
    finally:
        conn.close()

    assert "CVE-2021-23017" in ids1
    assert ids1 == ids2
    assert calls["n"] == 1  # second call served from cache, no new fetch


def test_kev_cache_refetches_after_ttl_expiry(db_path, monkeypatch):
    db.init_db(db_path).close()
    conn = db.connect(db_path)
    calls = {"n": 0}

    def counting_fetch():
        calls["n"] += 1
        return kev_catalog(["CVE-2021-23017"])

    monkeypatch.setattr(enrich, "fetch_kev_catalog", counting_fetch)

    try:
        enrich.get_kev_ids(conn)
        # backdate the cache beyond the TTL
        conn.execute(
            "UPDATE kev_cache SET fetched_at = datetime('now', '-2 days')"
        )
        conn.commit()
        enrich.get_kev_ids(conn)
    finally:
        conn.close()

    assert calls["n"] == 2  # stale cache forced a re-fetch


# --------------------------------------------------------------------------
# Exploit-DB (public-exploit) enrichment — schema + extraction
# --------------------------------------------------------------------------

def test_init_db_adds_exploit_column(db_path):
    conn = db.init_db(db_path)
    try:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(findings)")}
    finally:
        conn.close()
    assert "exploit" in cols


def test_migration_adds_exploit_to_legacy_findings_table(db_path):
    """A DB created before the exploit column must gain it on next init_db
    without losing data (the column lands with its 0 default)."""
    conn = sqlite3.connect(str(db_path))
    conn.executescript(
        """
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_id INTEGER NOT NULL,
            cve_id TEXT NOT NULL,
            summary TEXT,
            severity TEXT,
            source TEXT NOT NULL DEFAULT 'osv.dev',
            epss_score REAL,
            kev INTEGER NOT NULL DEFAULT 0,
            matched_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(service_id, cve_id)
        );
        CREATE TABLE assets (id INTEGER PRIMARY KEY, ip TEXT);
        CREATE TABLE services (id INTEGER PRIMARY KEY);
        CREATE TABLE cruise_runs (id INTEGER PRIMARY KEY, snapshot TEXT);
        INSERT INTO findings (service_id, cve_id, summary, severity)
            VALUES (1, 'CVE-2019-0001', 'legacy', 'HIGH');
        """
    )
    conn.commit()
    conn.close()

    db.init_db(db_path).close()

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(findings)")}
        row = conn.execute(
            "SELECT cve_id, exploit FROM findings WHERE cve_id='CVE-2019-0001'"
        ).fetchone()
    finally:
        conn.close()
    assert "exploit" in cols
    assert row["cve_id"] == "CVE-2019-0001"  # legacy row preserved
    assert row["exploit"] == 0  # default applied


def test_exploit_ids_from_index_extracts_cves():
    index = exploitdb_index(["CVE-2021-44228", "CVE-2017-0144"])
    ids = enrich.exploit_ids_from_index(index)
    assert ids == {"CVE-2021-44228", "CVE-2017-0144"}


def test_exploit_ids_from_index_is_case_insensitive_and_ignores_non_cve_codes():
    index = (
        "id,codes\n"
        "1,cve-2021-44228;OSVDB-99999\n"   # lower-case CVE + a non-CVE code
        "2,GHSA-xxxx-yyyy;EDB-1234\n"       # no CVE at all
    )
    ids = enrich.exploit_ids_from_index(index)
    assert ids == {"CVE-2021-44228"}  # normalised to upper, OSVDB/GHSA ignored


def test_exploit_ids_from_index_handles_empty_index():
    assert enrich.exploit_ids_from_index("") == set()
    assert enrich.exploit_ids_from_index("id,codes\n") == set()


def test_enrich_finding_marks_exploit_when_cve_in_edb():
    conn = db.init_db(":memory:")
    try:
        # query_epss is a network seam; stub it on the module under test.
        import ossuary.enrich as e
        orig = e.query_epss
        e.query_epss = lambda cve_id: 0.1
        try:
            ann = enrich.enrich_finding(
                conn, "CVE-2021-44228", set(), {"CVE-2021-44228"}
            )
        finally:
            e.query_epss = orig
    finally:
        conn.close()
    assert ann["exploit"] == 1
    assert ann["kev"] == 0


def test_enrich_finding_exploit_zero_when_absent_or_unset():
    conn = db.init_db(":memory:")
    try:
        import ossuary.enrich as e
        orig = e.query_epss
        e.query_epss = lambda cve_id: 0.1
        try:
            # CVE not in the EDB set
            a = enrich.enrich_finding(conn, "CVE-2000-0001", set(), {"CVE-9999-0000"})
            # exploit_ids omitted entirely -> historical behaviour, exploit=0
            b = enrich.enrich_finding(conn, "CVE-2000-0001", set())
        finally:
            e.query_epss = orig
    finally:
        conn.close()
    assert a["exploit"] == 0
    assert b["exploit"] == 0


# --------------------------------------------------------------------------
# Exploit-DB cache (TTL)
# --------------------------------------------------------------------------

def test_exploitdb_index_is_cached_across_calls(db_path, monkeypatch):
    db.init_db(db_path).close()
    conn = db.connect(db_path)
    calls = {"n": 0}

    def counting_fetch():
        calls["n"] += 1
        return exploitdb_index(["CVE-2021-44228"])

    monkeypatch.setattr(enrich, "fetch_exploitdb_index", counting_fetch)

    try:
        ids1 = enrich.get_exploit_ids(conn)
        ids2 = enrich.get_exploit_ids(conn)
    finally:
        conn.close()

    assert "CVE-2021-44228" in ids1
    assert ids1 == ids2
    assert calls["n"] == 1  # second call served from cache, no new fetch


def test_exploitdb_cache_refetches_after_ttl_expiry(db_path, monkeypatch):
    db.init_db(db_path).close()
    conn = db.connect(db_path)
    calls = {"n": 0}

    def counting_fetch():
        calls["n"] += 1
        return exploitdb_index(["CVE-2021-44228"])

    monkeypatch.setattr(enrich, "fetch_exploitdb_index", counting_fetch)

    try:
        enrich.get_exploit_ids(conn)
        conn.execute(
            "UPDATE exploitdb_cache SET fetched_at = datetime('now', '-2 days')"
        )
        conn.commit()
        enrich.get_exploit_ids(conn)
    finally:
        conn.close()

    assert calls["n"] == 2  # stale cache forced a re-fetch


# --------------------------------------------------------------------------
# end-to-end through match_cves
# --------------------------------------------------------------------------

def test_match_cves_marks_exploit_when_cve_in_edb(db_path, monkeypatch):
    _seed_service(db_path, "nginx", "1.18.0")

    monkeypatch.setattr(
        cves,
        "query_osv",
        lambda product, version: {
            "vulns": [
                {"id": "GHSA-x", "aliases": ["CVE-2021-23017"], "summary": "x",
                 "severity": []}
            ]
        },
    )
    monkeypatch.setattr(enrich, "query_epss", lambda cve_id: 0.5)
    monkeypatch.setattr(enrich, "fetch_kev_catalog", lambda: kev_catalog([]))
    monkeypatch.setattr(
        enrich, "fetch_exploitdb_index", lambda: exploitdb_index(["CVE-2021-23017"])
    )

    cves.match_cves(db_path, enrich_findings=True)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT kev, exploit FROM findings").fetchone()
    finally:
        conn.close()
    assert row["exploit"] == 1
    assert row["kev"] == 0  # exploit availability is independent of KEV


def test_match_cves_exploit_zero_when_cve_absent_from_edb(db_path, monkeypatch):
    _seed_service(db_path, "nginx", "1.18.0")

    monkeypatch.setattr(
        cves,
        "query_osv",
        lambda product, version: {
            "vulns": [
                {"id": "GHSA-x", "aliases": ["CVE-2021-23017"], "summary": "x",
                 "severity": []}
            ]
        },
    )
    monkeypatch.setattr(enrich, "query_epss", lambda cve_id: 0.5)
    monkeypatch.setattr(enrich, "fetch_kev_catalog", lambda: kev_catalog([]))
    monkeypatch.setattr(
        enrich, "fetch_exploitdb_index", lambda: exploitdb_index(["CVE-9999-0000"])
    )

    cves.match_cves(db_path, enrich_findings=True)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT exploit FROM findings").fetchone()
    finally:
        conn.close()
    assert row["exploit"] == 0


def test_match_cves_fetches_edb_index_once_per_run(db_path, monkeypatch):
    """Two services, two findings — the EDB index is resolved a single time."""
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", None, "up")
        db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
        db.upsert_service(conn, aid, 443, "tcp", "https", "nginx", "1.18.0", None)
        conn.commit()
    finally:
        conn.close()

    monkeypatch.setattr(
        cves,
        "query_osv",
        lambda product, version: {
            "vulns": [
                {"id": "GHSA-x", "aliases": ["CVE-2021-23017"], "summary": "x",
                 "severity": []}
            ]
        },
    )
    monkeypatch.setattr(enrich, "query_epss", lambda cve_id: 0.5)
    monkeypatch.setattr(enrich, "fetch_kev_catalog", lambda: kev_catalog([]))

    calls = {"n": 0}

    def counting_fetch():
        calls["n"] += 1
        return exploitdb_index(["CVE-2021-23017"])

    monkeypatch.setattr(enrich, "fetch_exploitdb_index", counting_fetch)

    cves.match_cves(db_path, enrich_findings=True)
    assert calls["n"] == 1  # cached after first resolve


def test_dump_surfaces_exploit_field(db_path, monkeypatch):
    """The exploit signal flows through dump's JSON findings dict."""
    from ossuary import dump

    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", None, "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
        db.upsert_finding(
            conn, sid, "CVE-2021-23017", "x", "9.8",
            epss_score=0.5, kev=0, exploit=1,
        )
        conn.commit()
        state = dump.build_state(conn)
    finally:
        conn.close()

    finding = state["assets"][0]["services"][0]["findings"][0]
    assert finding["exploit"] == 1
