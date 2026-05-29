"""Tests for JSON export (criterion 7) and CSV/Markdown export (POST_V01 #6)."""

from __future__ import annotations

import csv
import html
import io
import json

import pytest

from ossuary import db, dump, tags

# Columns shared by the flat (CSV / Markdown) exports — one finding per row,
# joining asset + service + finding context.
FLAT_COLUMNS = [
    "ip",
    "hostname",
    "asset_state",
    "discovered_at",
    "tags",
    "port",
    "protocol",
    "service_name",
    "product",
    "version",
    "cpe",
    "fingerprinted_at",
    "cve_id",
    "summary",
    "severity",
    "source",
    "epss_score",
    "kev",
    "exploit",
    "matched_at",
]


def test_dump_emits_nested_engagement_state(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
        db.upsert_finding(conn, sid, "CVE-2021-23017", "off-by-one", "7.7")
        conn.commit()
    finally:
        conn.close()

    out = dump.dump(db_path, "json")
    state = json.loads(out)

    assert len(state["assets"]) == 1
    asset = state["assets"][0]
    assert asset["ip"] == "10.10.0.5"
    assert asset["services"][0]["product"] == "nginx"
    assert asset["services"][0]["findings"][0]["cve_id"] == "CVE-2021-23017"


def test_dump_empty_db_is_valid_json(db_path):
    db.init_db(db_path).close()
    state = json.loads(dump.dump(db_path, "json"))
    assert state == {"assets": []}


def test_dump_rejects_unknown_format(db_path):
    db.init_db(db_path).close()
    with pytest.raises(ValueError, match="unsupported dump format"):
        dump.dump(db_path, "yaml")


# --------------------------------------------------------------------------
# CSV export (POST_V01 Rank 6)
# --------------------------------------------------------------------------

def _seed_one_finding(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", "cpe:/a:nginx")
        db.upsert_finding(conn, sid, "CVE-2021-23017", "off-by-one", "7.7")
        conn.commit()
    finally:
        conn.close()


def test_dump_csv_has_header_and_one_row_per_finding(db_path):
    _seed_one_finding(db_path)

    out = dump.dump(db_path, "csv")
    rows = list(csv.reader(io.StringIO(out)))

    assert rows[0] == FLAT_COLUMNS
    assert len(rows) == 2  # header + one finding
    row = dict(zip(FLAT_COLUMNS, rows[1]))
    assert row["ip"] == "10.10.0.5"
    assert row["hostname"] == "host-a"
    assert row["port"] == "80"
    assert row["product"] == "nginx"
    assert row["cpe"] == "cpe:/a:nginx"
    assert row["cve_id"] == "CVE-2021-23017"
    assert row["severity"] == "7.7"


def test_dump_csv_emits_service_row_when_no_findings(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.9", None, "up")
        db.upsert_service(conn, aid, 22, "tcp", "ssh", "OpenSSH", "8.2", None)
        conn.commit()
    finally:
        conn.close()

    rows = list(csv.reader(io.StringIO(dump.dump(db_path, "csv"))))
    assert len(rows) == 2  # header + one service row, empty finding cols
    row = dict(zip(FLAT_COLUMNS, rows[1]))
    assert row["port"] == "22"
    assert row["service_name"] == "ssh"
    assert row["cve_id"] == ""
    assert row["severity"] == ""


def test_dump_csv_empty_db_is_header_only(db_path):
    db.init_db(db_path).close()
    rows = list(csv.reader(io.StringIO(dump.dump(db_path, "csv"))))
    assert rows == [FLAT_COLUMNS]


def test_dump_csv_quotes_commas_in_summary(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
        db.upsert_finding(conn, sid, "CVE-2021-1", "heap overflow, then RCE", "9.8")
        conn.commit()
    finally:
        conn.close()

    out = dump.dump(db_path, "csv")
    rows = list(csv.reader(io.StringIO(out)))
    row = dict(zip(FLAT_COLUMNS, rows[1]))
    assert row["summary"] == "heap overflow, then RCE"


# --------------------------------------------------------------------------
# Markdown export (POST_V01 Rank 6)
# --------------------------------------------------------------------------

def test_dump_markdown_emits_pipe_table(db_path):
    _seed_one_finding(db_path)

    out = dump.dump(db_path, "markdown")
    lines = out.splitlines()

    # header row + separator row + one data row
    assert lines[0].startswith("|") and lines[0].endswith("|")
    header_cells = [c.strip() for c in lines[0].strip("|").split("|")]
    assert header_cells == FLAT_COLUMNS
    # GFM separator row of dashes
    sep_cells = [c.strip() for c in lines[1].strip("|").split("|")]
    assert all(set(c) == {"-"} for c in sep_cells)
    assert len(lines) == 3
    assert "10.10.0.5" in lines[2]
    assert "CVE-2021-23017" in lines[2]


def test_dump_markdown_escapes_pipes_in_cells(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
        db.upsert_finding(conn, sid, "CVE-2021-2", "a | b pipe injection", "5.0")
        conn.commit()
    finally:
        conn.close()

    out = dump.dump(db_path, "markdown")
    data_line = out.splitlines()[2]
    # the literal pipe inside the summary must be escaped so the table stays intact
    assert r"a \| b pipe injection" in data_line


def test_dump_markdown_empty_db_is_header_and_separator_only(db_path):
    db.init_db(db_path).close()
    lines = dump.dump(db_path, "markdown").splitlines()
    assert len(lines) == 2  # header + separator, no data rows


def test_dump_csv_and_markdown_cover_same_fields_as_json(db_path):
    _seed_one_finding(db_path)
    # JSON carries the same underlying data; the flat exports must surface every
    # finding-level and service-level field the JSON dump exposes.
    state = json.loads(dump.dump(db_path, "json"))
    finding = state["assets"][0]["services"][0]["findings"][0]
    for key in finding:
        assert key in FLAT_COLUMNS


# --------------------------------------------------------------------------
# Actionability filters: --min-epss / --min-severity / --kev-only (POST_V01)
# --------------------------------------------------------------------------

def _seed_mixed_findings(db_path):
    """Two services on one asset with findings spanning the signal spectrum.

    svc-80 (nginx):  high-EPSS KEV CVE, plus a cold low-EPSS non-KEV CVE.
    svc-22 (ssh):    a mid severity, no-EPSS, non-KEV CVE.
    """
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        s80 = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
        s22 = db.upsert_service(conn, aid, 22, "tcp", "ssh", "OpenSSH", "8.2", None)
        # hot: exploited in the wild, high EPSS, high severity
        db.upsert_finding(
            conn, s80, "CVE-HOT", "actively exploited", "9.8",
            epss_score=0.94, kev=1,
        )
        # cold: low EPSS, not in KEV, low severity
        db.upsert_finding(
            conn, s80, "CVE-COLD", "theoretical", "3.1",
            epss_score=0.02, kev=0,
        )
        # mid: medium severity but no EPSS score and not in KEV
        db.upsert_finding(
            conn, s22, "CVE-MID", "needs auth", "6.5",
            epss_score=None, kev=0,
        )
        conn.commit()
    finally:
        conn.close()


def _cve_ids(state):
    return {
        f["cve_id"]
        for a in state["assets"]
        for s in a["services"]
        for f in s["findings"]
    }


def test_dump_no_filters_returns_full_inventory(db_path):
    _seed_mixed_findings(db_path)
    state = json.loads(dump.dump(db_path, "json"))
    assert _cve_ids(state) == {"CVE-HOT", "CVE-COLD", "CVE-MID"}


def test_dump_kev_only_keeps_only_kev_findings(db_path):
    _seed_mixed_findings(db_path)
    state = json.loads(dump.dump(db_path, "json", kev_only=True))
    assert _cve_ids(state) == {"CVE-HOT"}


def test_dump_min_epss_excludes_low_and_missing_epss(db_path):
    _seed_mixed_findings(db_path)
    state = json.loads(dump.dump(db_path, "json", min_epss=0.5))
    # CVE-COLD (0.02) is below the floor; CVE-MID (no score) is excluded.
    assert _cve_ids(state) == {"CVE-HOT"}


def test_dump_min_severity_excludes_low_and_unparseable(db_path):
    _seed_mixed_findings(db_path)
    state = json.loads(dump.dump(db_path, "json", min_severity=6.0))
    # CVE-COLD (3.1) drops; CVE-MID (6.5) and CVE-HOT (9.8) survive.
    assert _cve_ids(state) == {"CVE-HOT", "CVE-MID"}


def test_dump_filters_prune_empty_services_and_assets(db_path):
    _seed_mixed_findings(db_path)
    # Only CVE-HOT (on svc-80) is KEV; svc-22 must be pruned, asset kept.
    state = json.loads(dump.dump(db_path, "json", kev_only=True))
    assert len(state["assets"]) == 1
    services = state["assets"][0]["services"]
    assert len(services) == 1
    assert services[0]["port"] == 80


def test_dump_filters_can_prune_an_asset_entirely(db_path):
    conn = db.init_db(db_path)
    try:
        # Asset with only a cold finding -> pruned when KEV-only.
        a1 = db.upsert_asset(conn, "10.10.0.5", "cold-host", "up")
        s1 = db.upsert_service(conn, a1, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, s1, "CVE-COLD", "x", "2.0", epss_score=0.01, kev=0)
        # Asset with a KEV finding -> kept.
        a2 = db.upsert_asset(conn, "10.10.0.6", "hot-host", "up")
        s2 = db.upsert_service(conn, a2, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, s2, "CVE-HOT", "y", "9.0", epss_score=0.9, kev=1)
        conn.commit()
    finally:
        conn.close()

    state = json.loads(dump.dump(db_path, "json", kev_only=True))
    ips = {a["ip"] for a in state["assets"]}
    assert ips == {"10.10.0.6"}


def test_dump_filters_compose(db_path):
    _seed_mixed_findings(db_path)
    # KEV-only AND min-severity 9.0: only CVE-HOT clears both.
    state = json.loads(
        dump.dump(db_path, "json", kev_only=True, min_severity=9.0)
    )
    assert _cve_ids(state) == {"CVE-HOT"}
    # KEV-only AND min-severity 10.0: nothing clears severity 10.
    state = json.loads(
        dump.dump(db_path, "json", kev_only=True, min_severity=10.0)
    )
    assert state == {"assets": []}


def test_dump_filters_apply_to_csv_export(db_path):
    _seed_mixed_findings(db_path)
    out = dump.dump(db_path, "csv", kev_only=True)
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0] == FLAT_COLUMNS
    assert len(rows) == 2  # header + only CVE-HOT
    row = dict(zip(FLAT_COLUMNS, rows[1]))
    assert row["cve_id"] == "CVE-HOT"
    assert row["kev"] == "1"


def test_dump_filters_apply_to_markdown_export(db_path):
    _seed_mixed_findings(db_path)
    out = dump.dump(db_path, "markdown", min_epss=0.5)
    lines = out.splitlines()
    assert len(lines) == 3  # header + separator + only CVE-HOT
    assert "CVE-HOT" in lines[2]
    assert "CVE-COLD" not in out
    assert "CVE-MID" not in out


# --------------------------------------------------------------------------
# Priority ordering (POST_V01 Rank 9 — `--sort-by-priority`)
# --------------------------------------------------------------------------

def _ordered_cve_ids(state, port):
    """The CVE ids of the findings on the given port, in emitted order."""
    for asset in state["assets"]:
        for svc in asset["services"]:
            if svc["port"] == port:
                return [f["cve_id"] for f in svc["findings"]]
    return []


def _seed_one_service_many_findings(db_path):
    """One service carrying findings that span every signal tier.

    Insertion order is deliberately NOT priority order, so a passing test
    proves the sort happened (and isn't an accident of insert/CVE-id order).
    """
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
        # cold non-KEV, low EPSS
        db.upsert_finding(conn, sid, "CVE-2020-COLD", "x", "3.1",
                          epss_score=0.02, kev=0)
        # KEV but lower EPSS than the other KEV
        db.upsert_finding(conn, sid, "CVE-2020-KEVLO", "x", "7.0",
                          epss_score=0.40, kev=1)
        # non-KEV, high EPSS
        db.upsert_finding(conn, sid, "CVE-2020-WARM", "x", "8.8",
                          epss_score=0.75, kev=0)
        # KEV, highest EPSS -> should lead
        db.upsert_finding(conn, sid, "CVE-2020-KEVHI", "x", "9.8",
                          epss_score=0.94, kev=1)
        conn.commit()
    finally:
        conn.close()


def test_dump_default_order_is_alphabetical_by_cve_id(db_path):
    _seed_one_service_many_findings(db_path)
    state = json.loads(dump.dump(db_path, "json"))
    # Unchanged historical behaviour: findings sorted by cve_id ascending.
    assert _ordered_cve_ids(state, 80) == [
        "CVE-2020-COLD",
        "CVE-2020-KEVHI",
        "CVE-2020-KEVLO",
        "CVE-2020-WARM",
    ]


def test_dump_sort_by_priority_orders_kev_then_epss(db_path):
    _seed_one_service_many_findings(db_path)
    state = json.loads(dump.dump(db_path, "json", sort_by_priority=True))
    # KEV findings first (highest EPSS within KEV leads), then non-KEV by EPSS.
    assert _ordered_cve_ids(state, 80) == [
        "CVE-2020-KEVHI",  # KEV, EPSS 0.94
        "CVE-2020-KEVLO",  # KEV, EPSS 0.40
        "CVE-2020-WARM",   # non-KEV, EPSS 0.75
        "CVE-2020-COLD",   # non-KEV, EPSS 0.02
    ]


def test_dump_sort_by_priority_severity_breaks_epss_ties(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.0", None)
        # Same KEV + same EPSS: higher numeric severity must lead.
        db.upsert_finding(conn, sid, "CVE-LOWSEV", "x", "5.0",
                          epss_score=0.50, kev=0)
        db.upsert_finding(conn, sid, "CVE-HIGHSEV", "x", "9.0",
                          epss_score=0.50, kev=0)
        conn.commit()
    finally:
        conn.close()
    state = json.loads(dump.dump(db_path, "json", sort_by_priority=True))
    assert _ordered_cve_ids(state, 80) == ["CVE-HIGHSEV", "CVE-LOWSEV"]


def test_dump_sort_by_priority_cve_id_breaks_full_ties(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.0", None)
        # Identical signal across the board -> deterministic cve_id ascending.
        db.upsert_finding(conn, sid, "CVE-BBB", "x", "5.0", epss_score=0.5, kev=0)
        db.upsert_finding(conn, sid, "CVE-AAA", "x", "5.0", epss_score=0.5, kev=0)
        conn.commit()
    finally:
        conn.close()
    state = json.loads(dump.dump(db_path, "json", sort_by_priority=True))
    assert _ordered_cve_ids(state, 80) == ["CVE-AAA", "CVE-BBB"]


def test_dump_sort_by_priority_missing_signals_sink_to_bottom(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, sid, "CVE-SIGNAL", "x", "7.0",
                          epss_score=0.30, kev=0)
        # No EPSS, blank severity -> ranks below any scored finding.
        db.upsert_finding(conn, sid, "CVE-BLANK", "x", None,
                          epss_score=None, kev=0)
        conn.commit()
    finally:
        conn.close()
    state = json.loads(dump.dump(db_path, "json", sort_by_priority=True))
    assert _ordered_cve_ids(state, 80) == ["CVE-SIGNAL", "CVE-BLANK"]


def test_dump_sort_by_priority_composes_with_filters(db_path):
    _seed_one_service_many_findings(db_path)
    # KEV-only filter leaves the two KEV findings, sorted by EPSS desc.
    state = json.loads(
        dump.dump(db_path, "json", kev_only=True, sort_by_priority=True)
    )
    assert _ordered_cve_ids(state, 80) == ["CVE-2020-KEVHI", "CVE-2020-KEVLO"]


def test_dump_sort_by_priority_applies_to_csv_export(db_path):
    _seed_one_service_many_findings(db_path)
    out = dump.dump(db_path, "csv", sort_by_priority=True)
    rows = list(csv.reader(io.StringIO(out)))
    cve_col = FLAT_COLUMNS.index("cve_id")
    emitted = [r[cve_col] for r in rows[1:]]
    assert emitted == [
        "CVE-2020-KEVHI",
        "CVE-2020-KEVLO",
        "CVE-2020-WARM",
        "CVE-2020-COLD",
    ]


# --------------------------------------------------------------------------
# HTML report export (POST_V01 Rank 11 — `--format html`)
# --------------------------------------------------------------------------

def test_dump_html_is_a_self_contained_document(db_path):
    _seed_one_finding(db_path)
    out = dump.dump(db_path, "html")
    # A standalone document: doctype, inline styles, no external asset refs.
    assert out.lstrip().startswith("<!DOCTYPE html>")
    assert "</html>" in out
    assert "<style>" in out
    assert "src=" not in out
    assert "href=" not in out


def test_dump_html_lists_assets_services_and_findings(db_path):
    _seed_one_finding(db_path)
    out = dump.dump(db_path, "html")
    assert "10.10.0.5" in out
    assert "host-a" in out
    assert "nginx" in out
    assert "CVE-2021-23017" in out
    assert "off-by-one" in out


def test_dump_html_escapes_html_in_finding_text(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(
            conn, sid, "CVE-XSS", "<script>alert(1)</script> & friends", "5.0"
        )
        conn.commit()
    finally:
        conn.close()

    out = dump.dump(db_path, "html")
    # The raw script tag must never appear unescaped in the report.
    assert "<script>alert(1)</script>" not in out
    assert html.escape("<script>alert(1)</script> & friends") in out


def test_dump_html_empty_db_is_still_valid_document(db_path):
    db.init_db(db_path).close()
    out = dump.dump(db_path, "html")
    assert out.lstrip().startswith("<!DOCTYPE html>")
    assert "</html>" in out
    # An explicit empty-state marker rather than a silent blank page.
    assert "No assets" in out


def test_dump_html_flags_kev_findings(db_path):
    _seed_mixed_findings(db_path)
    out = dump.dump(db_path, "html")
    # The KEV finding carries a visible KEV badge; the cold one does not gain one.
    assert "KEV" in out
    # Severity tiering classes are emitted so findings are colour-coded.
    assert "sev-" in out


def test_dump_html_filters_apply(db_path):
    _seed_mixed_findings(db_path)
    out = dump.dump(db_path, "html", kev_only=True)
    assert "CVE-HOT" in out
    assert "CVE-COLD" not in out
    assert "CVE-MID" not in out


def test_dump_html_sort_by_priority_orders_findings(db_path):
    _seed_one_service_many_findings(db_path)
    out = dump.dump(db_path, "html", sort_by_priority=True)
    # The hottest KEV finding must appear before the cold non-KEV one.
    assert out.index("CVE-2020-KEVHI") < out.index("CVE-2020-COLD")


def test_dump_html_is_listed_as_supported_format():
    assert "html" in dump.SUPPORTED_FORMATS


# --------------------------------------------------------------------------
# SARIF v2.1.0 export (POST_V01 Rank 14 — `--format sarif`)
# --------------------------------------------------------------------------

def _sarif_run(out):
    """Parse a SARIF dump and return its single run object."""
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert len(doc["runs"]) == 1
    return doc["runs"][0]


def test_dump_sarif_is_listed_as_supported_format():
    assert "sarif" in dump.SUPPORTED_FORMATS


def test_dump_sarif_is_valid_2_1_0_document(db_path):
    _seed_one_finding(db_path)
    run = _sarif_run(dump.dump(db_path, "sarif"))
    driver = run["tool"]["driver"]
    assert driver["name"] == "ossuary"
    assert "version" in driver
    # One result per finding, one rule per distinct CVE.
    assert len(run["results"]) == 1
    assert len(driver["rules"]) == 1


def test_dump_sarif_empty_db_has_empty_results(db_path):
    db.init_db(db_path).close()
    run = _sarif_run(dump.dump(db_path, "sarif"))
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_dump_sarif_result_carries_location_and_rule(db_path):
    _seed_one_finding(db_path)
    run = _sarif_run(dump.dump(db_path, "sarif"))
    result = run["results"][0]
    assert result["ruleId"] == "CVE-2021-23017"
    # The host:proto/port locates the finding.
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "10.10.0.5:tcp/80"
    # ruleIndex points at the matching rule entry.
    rule = run["tool"]["driver"]["rules"][result["ruleIndex"]]
    assert rule["id"] == "CVE-2021-23017"


def test_dump_sarif_carries_epss_kev_severity_in_properties(db_path):
    _seed_mixed_findings(db_path)
    run = _sarif_run(dump.dump(db_path, "sarif"))
    by_cve = {r["ruleId"]: r for r in run["results"]}
    hot = by_cve["CVE-HOT"]["properties"]
    assert hot["kev"] is True
    assert hot["epss_score"] == 0.94
    assert hot["severity"] == "9.8"


def test_dump_sarif_kev_finding_is_error_level(db_path):
    _seed_mixed_findings(db_path)
    run = _sarif_run(dump.dump(db_path, "sarif"))
    by_cve = {r["ruleId"]: r for r in run["results"]}
    # KEV -> error regardless of CVSS; cold low-severity -> note; mid -> warning.
    assert by_cve["CVE-HOT"]["level"] == "error"
    assert by_cve["CVE-COLD"]["level"] == "note"
    assert by_cve["CVE-MID"]["level"] == "warning"


def test_dump_sarif_blank_severity_non_kev_is_warning(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, sid, "CVE-BLANK", "x", None, epss_score=None, kev=0)
        conn.commit()
    finally:
        conn.close()
    run = _sarif_run(dump.dump(db_path, "sarif"))
    assert run["results"][0]["level"] == "warning"


def test_dump_sarif_deduplicates_rules_across_hosts(db_path):
    conn = db.init_db(db_path)
    try:
        # Same CVE matched on two different hosts -> one rule, two results.
        a1 = db.upsert_asset(conn, "10.10.0.5", "h1", "up")
        s1 = db.upsert_service(conn, a1, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, s1, "CVE-SHARED", "x", "7.0")
        a2 = db.upsert_asset(conn, "10.10.0.6", "h2", "up")
        s2 = db.upsert_service(conn, a2, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, s2, "CVE-SHARED", "x", "7.0")
        conn.commit()
    finally:
        conn.close()
    run = _sarif_run(dump.dump(db_path, "sarif"))
    assert len(run["results"]) == 2
    assert len(run["tool"]["driver"]["rules"]) == 1
    # Both results reference the single rule.
    assert {r["ruleIndex"] for r in run["results"]} == {0}


def test_dump_sarif_escapes_nothing_but_keeps_text_intact(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, sid, "CVE-TXT", "heap overflow & RCE", "9.0")
        conn.commit()
    finally:
        conn.close()
    run = _sarif_run(dump.dump(db_path, "sarif"))
    # JSON carries the raw text safely; the summary survives round-trip.
    assert "heap overflow & RCE" in run["results"][0]["message"]["text"]
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["fullDescription"]["text"] == "heap overflow & RCE"


def test_dump_sarif_cve_rule_has_nvd_help_uri(db_path):
    _seed_one_finding(db_path)
    run = _sarif_run(dump.dump(db_path, "sarif"))
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["helpUri"] == "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"


def test_dump_sarif_filters_apply(db_path):
    _seed_mixed_findings(db_path)
    run = _sarif_run(dump.dump(db_path, "sarif", kev_only=True))
    cves = {r["ruleId"] for r in run["results"]}
    assert cves == {"CVE-HOT"}


def test_dump_sarif_sort_by_priority_orders_results(db_path):
    _seed_one_service_many_findings(db_path)
    run = _sarif_run(dump.dump(db_path, "sarif", sort_by_priority=True))
    emitted = [r["ruleId"] for r in run["results"]]
    assert emitted == [
        "CVE-2020-KEVHI",
        "CVE-2020-KEVLO",
        "CVE-2020-WARM",
        "CVE-2020-COLD",
    ]


def test_dump_sarif_omits_service_with_no_findings(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.9", None, "up")
        db.upsert_service(conn, aid, 22, "tcp", "ssh", "OpenSSH", "8.2", None)
        conn.commit()
    finally:
        conn.close()
    # Unlike CSV (which emits a service row), SARIF is finding-centric:
    # a service with no finding produces no result.
    run = _sarif_run(dump.dump(db_path, "sarif"))
    assert run["results"] == []


# --------------------------------------------------------------------------
# Recency filtering: --since / --until on matched_at (POST_V01 Rank 16)
# --------------------------------------------------------------------------

def _seed_dated_findings(db_path):
    """Three findings on one service, each with an explicit matched_at date.

    matched_at is normally stamped by datetime('now'); these tests override it
    so the recency window can be exercised deterministically.

      CVE-OLD  matched 2026-01-10
      CVE-MID  matched 2026-03-15
      CVE-NEW  matched 2026-05-29 14:30:00 (with a time component)
    """
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
        db.upsert_finding(conn, sid, "CVE-OLD", "x", "5.0")
        db.upsert_finding(conn, sid, "CVE-MID", "y", "5.0")
        db.upsert_finding(conn, sid, "CVE-NEW", "z", "5.0")
        conn.execute(
            "UPDATE findings SET matched_at = ? WHERE cve_id = ?",
            ("2026-01-10 09:00:00", "CVE-OLD"),
        )
        conn.execute(
            "UPDATE findings SET matched_at = ? WHERE cve_id = ?",
            ("2026-03-15 12:00:00", "CVE-MID"),
        )
        conn.execute(
            "UPDATE findings SET matched_at = ? WHERE cve_id = ?",
            ("2026-05-29 14:30:00", "CVE-NEW"),
        )
        conn.commit()
    finally:
        conn.close()


def test_dump_no_recency_window_returns_all(db_path):
    _seed_dated_findings(db_path)
    state = json.loads(dump.dump(db_path, "json"))
    assert _cve_ids(state) == {"CVE-OLD", "CVE-MID", "CVE-NEW"}


def test_dump_since_keeps_findings_on_or_after_date(db_path):
    _seed_dated_findings(db_path)
    state = json.loads(dump.dump(db_path, "json", since="2026-03-15"))
    # CVE-OLD (Jan) drops; CVE-MID (exactly the bound) and CVE-NEW survive.
    assert _cve_ids(state) == {"CVE-MID", "CVE-NEW"}


def test_dump_until_keeps_findings_on_or_before_date(db_path):
    _seed_dated_findings(db_path)
    state = json.loads(dump.dump(db_path, "json", until="2026-03-15"))
    # CVE-NEW (May) drops; CVE-OLD and CVE-MID survive.
    assert _cve_ids(state) == {"CVE-OLD", "CVE-MID"}


def test_dump_bare_date_until_covers_the_whole_day(db_path):
    _seed_dated_findings(db_path)
    # CVE-NEW is matched at 14:30 on 2026-05-29; a bare-date upper bound must
    # include that day's later timestamps, not exclude them.
    state = json.loads(dump.dump(db_path, "json", until="2026-05-29"))
    assert "CVE-NEW" in _cve_ids(state)


def test_dump_since_and_until_bound_a_window(db_path):
    _seed_dated_findings(db_path)
    state = json.loads(
        dump.dump(db_path, "json", since="2026-02-01", until="2026-04-01")
    )
    # Only CVE-MID (2026-03-15) falls inside the window.
    assert _cve_ids(state) == {"CVE-MID"}


def test_dump_recency_window_with_datetime_bound(db_path):
    _seed_dated_findings(db_path)
    # A full datetime upper bound just after noon on the MID day excludes the
    # 12:00 MID timestamp's same-second boundary inclusively.
    state = json.loads(dump.dump(db_path, "json", until="2026-03-15 12:00:00"))
    assert _cve_ids(state) == {"CVE-OLD", "CVE-MID"}


def test_dump_recency_excludes_finding_with_blank_matched_at(db_path):
    _seed_dated_findings(db_path)
    conn = db.connect(db_path)
    try:
        # matched_at is NOT NULL in the schema, but a blank string is just as
        # un-placeable on the timeline — a window must exclude it.
        conn.execute("UPDATE findings SET matched_at = '' WHERE cve_id = 'CVE-MID'")
        conn.commit()
    finally:
        conn.close()
    state = json.loads(dump.dump(db_path, "json", since="2026-01-01"))
    assert "CVE-MID" not in _cve_ids(state)
    assert _cve_ids(state) == {"CVE-OLD", "CVE-NEW"}


def test_dump_recency_prunes_empty_services_and_assets(db_path):
    _seed_dated_findings(db_path)
    # A window that no finding falls into prunes the service and asset entirely.
    state = json.loads(
        dump.dump(db_path, "json", since="2027-01-01")
    )
    assert state == {"assets": []}


def test_dump_recency_composes_with_actionability_filters(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
        # Recent + KEV -> survives both filters.
        db.upsert_finding(conn, sid, "CVE-RECENT-KEV", "x", "9.8",
                          epss_score=0.9, kev=1)
        # Recent but not KEV -> dropped by kev_only.
        db.upsert_finding(conn, sid, "CVE-RECENT-COLD", "y", "3.0",
                          epss_score=0.01, kev=0)
        # Old + KEV -> dropped by the recency window.
        db.upsert_finding(conn, sid, "CVE-OLD-KEV", "z", "9.0",
                          epss_score=0.8, kev=1)
        conn.execute(
            "UPDATE findings SET matched_at = '2026-05-29 10:00:00' "
            "WHERE cve_id IN ('CVE-RECENT-KEV', 'CVE-RECENT-COLD')"
        )
        conn.execute(
            "UPDATE findings SET matched_at = '2026-01-01 10:00:00' "
            "WHERE cve_id = 'CVE-OLD-KEV'"
        )
        conn.commit()
    finally:
        conn.close()
    state = json.loads(
        dump.dump(db_path, "json", kev_only=True, since="2026-05-01")
    )
    assert _cve_ids(state) == {"CVE-RECENT-KEV"}


def test_dump_recency_applies_to_csv_export(db_path):
    _seed_dated_findings(db_path)
    out = dump.dump(db_path, "csv", since="2026-05-01")
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0] == FLAT_COLUMNS
    assert len(rows) == 2  # header + only CVE-NEW
    row = dict(zip(FLAT_COLUMNS, rows[1]))
    assert row["cve_id"] == "CVE-NEW"


def test_dump_recency_composes_with_sort_by_priority(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
        db.upsert_finding(conn, sid, "CVE-A-COLD", "x", "3.0",
                          epss_score=0.02, kev=0)
        db.upsert_finding(conn, sid, "CVE-B-HOT", "y", "9.8",
                          epss_score=0.94, kev=1)
        conn.execute(
            "UPDATE findings SET matched_at = '2026-05-29 10:00:00'"
        )
        conn.commit()
    finally:
        conn.close()
    state = json.loads(
        dump.dump(db_path, "json", since="2026-05-01", sort_by_priority=True)
    )
    # Both survive the window; priority order puts the KEV finding first.
    assert _ordered_cve_ids(state, 80) == ["CVE-B-HOT", "CVE-A-COLD"]


def test_normalise_until_extends_bare_date_to_end_of_day():
    assert dump._normalise_until("2026-05-29") == "2026-05-29 23:59:59"


def test_normalise_until_leaves_datetime_untouched():
    assert dump._normalise_until("2026-05-29 08:00:00") == "2026-05-29 08:00:00"


def test_normalise_until_passes_none_through():
    assert dump._normalise_until(None) is None


# --------------------------------------------------------------------------
# Issue-tracker import CSV export (Jira / Linear)
# --------------------------------------------------------------------------

JIRA_COLUMNS = [
    "Summary",
    "Description",
    "Priority",
    "Labels",
    "Component",
    "CVE",
    "EPSS",
    "KEV",
    "Severity",
    "Host",
    "Port",
]


def _jira_rows(out: str) -> list[dict]:
    """Parse the jira-format CSV into a list of dict rows (header-keyed)."""
    reader = csv.reader(io.StringIO(out))
    rows = list(reader)
    assert rows[0] == JIRA_COLUMNS
    return [dict(zip(JIRA_COLUMNS, r)) for r in rows[1:]]


def test_dump_jira_is_listed_as_supported_format():
    assert "jira" in dump.SUPPORTED_FORMATS


def test_dump_jira_has_issue_tracker_header():
    # The first four columns are the ones Jira / Linear map onto issue fields.
    assert dump.JIRA_COLUMNS[:4] == ["Summary", "Description", "Priority", "Labels"]


def test_dump_jira_emits_one_row_per_finding(db_path):
    _seed_one_finding(db_path)
    rows = _jira_rows(dump.dump(db_path, "jira"))
    assert len(rows) == 1
    row = rows[0]
    assert row["CVE"] == "CVE-2021-23017"
    assert row["Host"] == "10.10.0.5 (host-a)"
    assert row["Port"] == "tcp/80"
    assert row["Severity"] == "7.7"


def test_dump_jira_empty_db_is_header_only(db_path):
    db.init_db(db_path).close()
    rows = _jira_rows(dump.dump(db_path, "jira"))
    assert rows == []


def test_dump_jira_omits_service_with_no_findings(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.9", None, "up")
        db.upsert_service(conn, aid, 22, "tcp", "ssh", "OpenSSH", "8.2", None)
        conn.commit()
    finally:
        conn.close()
    # Finding-centric: a service with no finding produces no ticket row.
    rows = _jira_rows(dump.dump(db_path, "jira"))
    assert rows == []


def test_dump_jira_summary_and_description_are_ticket_shaped(db_path):
    _seed_one_finding(db_path)
    row = _jira_rows(dump.dump(db_path, "jira"))[0]
    # Summary is a human title naming the CVE and host.
    assert "CVE-2021-23017" in row["Summary"]
    assert "10.10.0.5 (host-a)" in row["Summary"]
    # Description carries the triage context, including the OSV summary text.
    assert "CVE: CVE-2021-23017" in row["Description"]
    assert "off-by-one" in row["Description"]


def test_dump_jira_priority_maps_from_live_signal(db_path):
    _seed_mixed_findings(db_path)
    by_cve = {r["CVE"]: r for r in _jira_rows(dump.dump(db_path, "jira"))}
    # KEV -> Highest; high EPSS/severity -> High; cold low -> Low; mid -> Medium.
    assert by_cve["CVE-HOT"]["Priority"] == "Highest"
    assert by_cve["CVE-COLD"]["Priority"] == "Low"
    assert by_cve["CVE-MID"]["Priority"] == "Medium"


def test_dump_jira_blank_signal_is_low_priority(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, sid, "CVE-BLANK", "x", None, epss_score=None, kev=0)
        conn.commit()
    finally:
        conn.close()
    row = _jira_rows(dump.dump(db_path, "jira"))[0]
    assert row["Priority"] == "Low"


def test_dump_jira_kev_finding_carries_kev_label(db_path):
    _seed_mixed_findings(db_path)
    by_cve = {r["CVE"]: r for r in _jira_rows(dump.dump(db_path, "jira"))}
    assert by_cve["CVE-HOT"]["KEV"] == "yes"
    assert "kev" in by_cve["CVE-HOT"]["Labels"].split(";")
    # A non-KEV finding has no kev label.
    assert by_cve["CVE-COLD"]["KEV"] == "no"
    assert "kev" not in by_cve["CVE-COLD"]["Labels"].split(";")


def test_dump_jira_labels_include_asset_tags(db_path):
    _seed_one_finding(db_path)
    tags.add_tag(db_path, "10.10.0.5", "in-scope")
    row = _jira_rows(dump.dump(db_path, "jira"))[0]
    assert "in-scope" in row["Labels"].split(";")


def test_dump_jira_component_reflects_service(db_path):
    _seed_one_finding(db_path)
    row = _jira_rows(dump.dump(db_path, "jira"))[0]
    assert row["Component"] == "nginx 1.18.0"


def test_dump_jira_epss_cell_formatted_and_blank_when_absent(db_path):
    _seed_mixed_findings(db_path)
    by_cve = {r["CVE"]: r for r in _jira_rows(dump.dump(db_path, "jira"))}
    assert by_cve["CVE-HOT"]["EPSS"] == "0.94"
    # No EPSS score -> empty cell, not "None".
    assert by_cve["CVE-MID"]["EPSS"] == ""


def test_dump_jira_honours_actionability_filters(db_path):
    _seed_mixed_findings(db_path)
    rows = _jira_rows(dump.dump(db_path, "jira", kev_only=True))
    # Only the KEV finding survives the filter.
    assert [r["CVE"] for r in rows] == ["CVE-HOT"]


def test_dump_jira_honours_tag_scope(db_path):
    _seed_mixed_findings(db_path)
    tags.add_tag(db_path, "10.10.0.5", "in-scope")
    rows = _jira_rows(dump.dump(db_path, "jira", tag="in-scope"))
    # The tagged host's findings all appear.
    assert {r["CVE"] for r in rows} == {"CVE-HOT", "CVE-COLD", "CVE-MID"}
    # A tag no asset carries scopes to nothing.
    assert _jira_rows(dump.dump(db_path, "jira", tag="nope")) == []


def test_dump_jira_sort_by_priority_orders_rows(db_path):
    _seed_mixed_findings(db_path)
    rows = _jira_rows(dump.dump(db_path, "jira", sort_by_priority=True))
    # Within svc-80 the KEV finding leads the cold one under priority order.
    cves_80 = [r["CVE"] for r in rows if r["Component"] == "nginx 1.18.0"]
    assert cves_80 == ["CVE-HOT", "CVE-COLD"]


def test_dump_jira_round_trips_through_csv_reader(db_path):
    # A finding summary with a comma / newline must survive CSV quoting intact.
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, sid, "CVE-CSV", "heap overflow, then RCE", "9.0")
        conn.commit()
    finally:
        conn.close()
    row = _jira_rows(dump.dump(db_path, "jira"))[0]
    assert "heap overflow, then RCE" in row["Description"]


# --------------------------------------------------------------------------
# CycloneDX 1.5 SBOM export (SBOM-linked findings — `--format cyclonedx`)
# --------------------------------------------------------------------------

def _bom(out):
    """Parse a CycloneDX dump and assert its document-level invariants."""
    doc = json.loads(out)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert "components" in doc
    assert "vulnerabilities" in doc
    return doc


def test_dump_cyclonedx_is_listed_as_supported_format():
    assert "cyclonedx" in dump.SUPPORTED_FORMATS


def test_dump_cyclonedx_rejected_format_still_errors(db_path):
    db.init_db(db_path).close()
    with pytest.raises(ValueError, match="unsupported dump format"):
        dump.dump(db_path, "toml")


def test_dump_cyclonedx_is_valid_1_5_document(db_path):
    _seed_one_finding(db_path)
    doc = _bom(dump.dump(db_path, "cyclonedx"))
    tool = doc["metadata"]["tools"][0]
    assert tool["name"] == "ossuary"
    assert "version" in tool
    # One component per service, one vulnerability per finding.
    assert len(doc["components"]) == 1
    assert len(doc["vulnerabilities"]) == 1


def test_dump_cyclonedx_empty_db_has_empty_arrays(db_path):
    db.init_db(db_path).close()
    doc = _bom(dump.dump(db_path, "cyclonedx"))
    assert doc["components"] == []
    assert doc["vulnerabilities"] == []


def test_dump_cyclonedx_component_carries_identifiers(db_path):
    _seed_one_finding(db_path)  # nginx 1.18.0 with cpe:/a:nginx on 10.10.0.5:tcp/80
    doc = _bom(dump.dump(db_path, "cyclonedx"))
    comp = doc["components"][0]
    assert comp["type"] == "application"
    assert comp["bom-ref"] == "10.10.0.5:tcp/80"
    assert comp["name"] == "nginx"
    assert comp["version"] == "1.18.0"
    assert comp["cpe"] == "cpe:/a:nginx"
    # A generic purl identifies the discovered software at the network layer.
    assert comp["purl"] == "pkg:generic/nginx@1.18.0"


def test_dump_cyclonedx_vulnerability_links_back_to_component(db_path):
    _seed_one_finding(db_path)
    doc = _bom(dump.dump(db_path, "cyclonedx"))
    comp_ref = doc["components"][0]["bom-ref"]
    vuln = doc["vulnerabilities"][0]
    assert vuln["id"] == "CVE-2021-23017"
    # The affects[].ref back-reference is the SBOM-to-findings link.
    assert vuln["affects"][0]["ref"] == comp_ref
    assert vuln["source"]["url"] == (
        "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"
    )
    assert vuln["ratings"][0]["severity"] == "high"  # CVSS 7.7 -> high
    assert vuln["ratings"][0]["score"] == 7.7


def test_dump_cyclonedx_carries_epss_kev_in_properties(db_path):
    _seed_mixed_findings(db_path)
    doc = _bom(dump.dump(db_path, "cyclonedx"))
    by_cve = {v["id"]: v for v in doc["vulnerabilities"]}
    hot_props = {p["name"]: p["value"] for p in by_cve["CVE-HOT"]["properties"]}
    assert hot_props["ossuary:kev"] == "true"
    assert hot_props["ossuary:epss"] == "0.94"
    cold_props = {p["name"]: p["value"] for p in by_cve["CVE-COLD"]["properties"]}
    assert cold_props["ossuary:kev"] == "false"


def test_dump_cyclonedx_blank_severity_is_unknown_rating(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, sid, "CVE-BLANK", "x", None, epss_score=None, kev=0)
        conn.commit()
    finally:
        conn.close()
    doc = _bom(dump.dump(db_path, "cyclonedx"))
    rating = doc["vulnerabilities"][0]["ratings"][0]
    assert rating["severity"] == "unknown"
    # No numeric score means no score / method keys on the rating.
    assert "score" not in rating


def test_dump_cyclonedx_severity_tiers(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, sid, "CVE-CRIT", "x", "9.8")
        db.upsert_finding(conn, sid, "CVE-HIGH", "x", "7.5")
        db.upsert_finding(conn, sid, "CVE-MEDM", "x", "5.0")
        db.upsert_finding(conn, sid, "CVE-LOWW", "x", "2.0")
        conn.commit()
    finally:
        conn.close()
    doc = _bom(dump.dump(db_path, "cyclonedx"))
    tiers = {v["id"]: v["ratings"][0]["severity"] for v in doc["vulnerabilities"]}
    assert tiers == {
        "CVE-CRIT": "critical",
        "CVE-HIGH": "high",
        "CVE-MEDM": "medium",
        "CVE-LOWW": "low",
    }


def test_dump_cyclonedx_emits_component_even_with_no_findings(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.9", None, "up")
        db.upsert_service(conn, aid, 22, "tcp", "ssh", "OpenSSH", "8.2", None)
        conn.commit()
    finally:
        conn.close()
    # An SBOM is a component inventory: a service with no finding is still a
    # discovered component, so it appears (unlike SARIF, which is finding-only).
    doc = _bom(dump.dump(db_path, "cyclonedx"))
    assert len(doc["components"]) == 1
    assert doc["components"][0]["name"] == "OpenSSH"
    assert doc["vulnerabilities"] == []


def test_dump_cyclonedx_links_shared_cve_to_each_component(db_path):
    conn = db.init_db(db_path)
    try:
        # Same CVE on two hosts -> two components, two distinct vuln entries,
        # each linked to its own component bom-ref.
        a1 = db.upsert_asset(conn, "10.10.0.5", "h1", "up")
        s1 = db.upsert_service(conn, a1, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, s1, "CVE-SHARED", "x", "7.0")
        a2 = db.upsert_asset(conn, "10.10.0.6", "h2", "up")
        s2 = db.upsert_service(conn, a2, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, s2, "CVE-SHARED", "x", "7.0")
        conn.commit()
    finally:
        conn.close()
    doc = _bom(dump.dump(db_path, "cyclonedx"))
    assert len(doc["components"]) == 2
    assert len(doc["vulnerabilities"]) == 2
    refs = {v["affects"][0]["ref"] for v in doc["vulnerabilities"]}
    assert refs == {"10.10.0.5:tcp/80", "10.10.0.6:tcp/80"}


def test_dump_cyclonedx_filters_apply(db_path):
    _seed_mixed_findings(db_path)
    doc = _bom(dump.dump(db_path, "cyclonedx", kev_only=True))
    cves = {v["id"] for v in doc["vulnerabilities"]}
    assert cves == {"CVE-HOT"}
    # The pruned service carries no component either (filtered build_state).
    assert len(doc["components"]) == 1
    assert doc["components"][0]["bom-ref"] == "10.10.0.5:tcp/80"


def test_dump_cyclonedx_sort_by_priority_orders_vulnerabilities(db_path):
    _seed_one_service_many_findings(db_path)
    doc = _bom(dump.dump(db_path, "cyclonedx", sort_by_priority=True))
    emitted = [v["id"] for v in doc["vulnerabilities"]]
    assert emitted == [
        "CVE-2020-KEVHI",
        "CVE-2020-KEVLO",
        "CVE-2020-WARM",
        "CVE-2020-COLD",
    ]


def test_dump_cyclonedx_purl_escapes_special_chars(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        # A product name with a space / slash must be percent-encoded in the purl.
        db.upsert_service(conn, aid, 80, "tcp", "http", "Acme Web/Server", "2.0", None)
        conn.commit()
    finally:
        conn.close()
    doc = _bom(dump.dump(db_path, "cyclonedx"))
    assert doc["components"][0]["purl"] == "pkg:generic/Acme%20Web%2FServer@2.0"


# --------------------------------------------------------------------------
# SPDX 2.3 SBOM export (`--format spdx`) — the ISO/IEC 5962:2021 companion
# --------------------------------------------------------------------------

def _spdx(out):
    """Parse an SPDX dump and assert its document-level invariants."""
    doc = json.loads(out)
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["dataLicense"] == "CC0-1.0"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert "packages" in doc
    assert "relationships" in doc
    return doc


def _pkg_security_refs(package):
    """The SECURITY/cve external-reference locators on an SPDX package."""
    return [
        r["referenceLocator"]
        for r in package.get("externalRefs", [])
        if r["referenceType"] == "cve"
    ]


def test_dump_spdx_is_listed_as_supported_format():
    assert "spdx" in dump.SUPPORTED_FORMATS


def test_dump_spdx_is_valid_2_3_document(db_path):
    _seed_one_finding(db_path)
    doc = _spdx(dump.dump(db_path, "spdx"))
    creators = doc["creationInfo"]["creators"]
    assert any(c.startswith("Tool: ossuary-") for c in creators)
    assert "created" in doc["creationInfo"]
    # One package per service.
    assert len(doc["packages"]) == 1
    # The document DESCRIBES each package.
    assert len(doc["relationships"]) == 1


def test_dump_spdx_empty_db_has_empty_arrays(db_path):
    db.init_db(db_path).close()
    doc = _spdx(dump.dump(db_path, "spdx"))
    assert doc["packages"] == []
    assert doc["relationships"] == []


def test_dump_spdx_package_carries_identifiers(db_path):
    _seed_one_finding(db_path)  # nginx 1.18.0 cpe:/a:nginx on 10.10.0.5:tcp/80
    doc = _spdx(dump.dump(db_path, "spdx"))
    pkg = doc["packages"][0]
    assert pkg["SPDXID"] == "SPDXRef-10.10.0.5-tcp-80"
    assert pkg["name"] == "nginx"
    assert pkg["versionInfo"] == "1.18.0"
    # SPDX requires these on every package.
    assert pkg["downloadLocation"] == "NOASSERTION"
    assert pkg["licenseConcluded"] == "NOASSERTION"
    ext = {r["referenceType"]: r["referenceLocator"] for r in pkg["externalRefs"]}
    assert ext["cpe23Type"] == "cpe:/a:nginx"
    assert ext["purl"] == "pkg:generic/nginx@1.18.0"


def test_dump_spdx_describes_relationship_targets_each_package(db_path):
    _seed_one_finding(db_path)
    doc = _spdx(dump.dump(db_path, "spdx"))
    pkg_id = doc["packages"][0]["SPDXID"]
    rel = doc["relationships"][0]
    assert rel["spdxElementId"] == "SPDXRef-DOCUMENT"
    assert rel["relationshipType"] == "DESCRIBES"
    assert rel["relatedSpdxElement"] == pkg_id


def test_dump_spdx_finding_becomes_security_external_ref(db_path):
    _seed_one_finding(db_path)
    doc = _spdx(dump.dump(db_path, "spdx"))
    refs = _pkg_security_refs(doc["packages"][0])
    assert refs == ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"]
    # The CVE ref records the live signal in its comment.
    cve_ref = next(
        r
        for r in doc["packages"][0]["externalRefs"]
        if r["referenceType"] == "cve"
    )
    assert cve_ref["referenceCategory"] == "SECURITY"
    assert "CVE-2021-23017" in cve_ref["comment"]
    assert "severity=7.7" in cve_ref["comment"]


def test_dump_spdx_security_ref_carries_epss_and_kev(db_path):
    _seed_mixed_findings(db_path)
    doc = _spdx(dump.dump(db_path, "spdx"))
    # CVE-HOT is on the nginx (80) package; find its cve ref comment.
    comments = [
        r["comment"]
        for pkg in doc["packages"]
        for r in pkg.get("externalRefs", [])
        if r["referenceType"] == "cve"
    ]
    hot = next(c for c in comments if "CVE-HOT" in c)
    assert "epss=0.94" in hot
    assert "kev" in hot
    cold = next(c for c in comments if "CVE-COLD" in c)
    assert "kev" not in cold


def test_dump_spdx_non_cve_finding_locator_is_the_raw_id(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, sid, "GHSA-xxxx", "advisory", "5.0")
        conn.commit()
    finally:
        conn.close()
    doc = _spdx(dump.dump(db_path, "spdx"))
    assert _pkg_security_refs(doc["packages"][0]) == ["GHSA-xxxx"]


def test_dump_spdx_emits_package_even_with_no_findings(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.9", None, "up")
        db.upsert_service(conn, aid, 22, "tcp", "ssh", "OpenSSH", "8.2", None)
        conn.commit()
    finally:
        conn.close()
    # An SBOM is a component inventory: a service with no finding is still a
    # discovered package, so it appears (like CycloneDX, unlike SARIF).
    doc = _spdx(dump.dump(db_path, "spdx"))
    assert len(doc["packages"]) == 1
    assert doc["packages"][0]["name"] == "OpenSSH"
    assert _pkg_security_refs(doc["packages"][0]) == []
    assert len(doc["relationships"]) == 1


def test_dump_spdx_ids_are_unique_and_valid(db_path):
    conn = db.init_db(db_path)
    try:
        a1 = db.upsert_asset(conn, "10.10.0.5", "h1", "up")
        db.upsert_service(conn, a1, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_service(conn, a1, 443, "tcp", "https", "nginx", "1.0", None)
        a2 = db.upsert_asset(conn, "10.10.0.6", "h2", "up")
        db.upsert_service(conn, a2, 80, "tcp", "http", "apache", "2.4", None)
        conn.commit()
    finally:
        conn.close()
    doc = _spdx(dump.dump(db_path, "spdx"))
    ids = [p["SPDXID"] for p in doc["packages"]]
    assert len(ids) == len(set(ids)) == 3
    # Every id is a valid SPDXRef-<alnum.-> identifier (no ':' or '/').
    for sid in ids:
        assert sid.startswith("SPDXRef-")
        assert all(c not in sid for c in (":", "/", " "))


def test_dump_spdx_filters_apply(db_path):
    _seed_mixed_findings(db_path)
    doc = _spdx(dump.dump(db_path, "spdx", kev_only=True))
    # Only the KEV finding's service survives the filter -> one package.
    assert len(doc["packages"]) == 1
    assert doc["packages"][0]["SPDXID"] == "SPDXRef-10.10.0.5-tcp-80"
    assert _pkg_security_refs(doc["packages"][0]) == [
        "https://nvd.nist.gov/vuln/detail/CVE-HOT"
    ]


def test_dump_spdx_sort_by_priority_orders_security_refs(db_path):
    _seed_one_service_many_findings(db_path)
    doc = _spdx(dump.dump(db_path, "spdx", sort_by_priority=True))
    refs = _pkg_security_refs(doc["packages"][0])
    # The per-finding CVE refs follow the priority order build_state imposes.
    assert refs == [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-KEVHI",
        "https://nvd.nist.gov/vuln/detail/CVE-2020-KEVLO",
        "https://nvd.nist.gov/vuln/detail/CVE-2020-WARM",
        "https://nvd.nist.gov/vuln/detail/CVE-2020-COLD",
    ]


def test_dump_spdx_honours_tag_scope(db_path):
    _seed_mixed_findings(db_path)  # all on 10.10.0.5
    conn = db.init_db(db_path)
    try:
        db.upsert_asset(conn, "10.10.0.9", "other", "up")
        aid = conn.execute(
            "SELECT id FROM assets WHERE ip = '10.10.0.9'"
        ).fetchone()["id"]
        db.upsert_service(conn, aid, 21, "tcp", "ftp", "vsftpd", "3.0", None)
        conn.commit()
    finally:
        conn.close()
    tags.add_tag(db_path, "10.10.0.5", "in-scope")
    doc = _spdx(dump.dump(db_path, "spdx", tag="in-scope"))
    # Only the tagged host's services appear; the ftp service is excluded.
    names = {p["name"] for p in doc["packages"]}
    assert names == {"nginx", "OpenSSH"}


# --------------------------------------------------------------------------
# OpenVEX export (standalone VEX document — the inverse of the import path)
# --------------------------------------------------------------------------

def _vex(out):
    """Parse a VEX dump and assert its document-level invariants."""
    doc = json.loads(out)
    assert doc["@context"].startswith("https://openvex.dev/ns/")
    assert "@id" in doc
    assert doc["author"].startswith("ossuary-")
    assert "timestamp" in doc
    assert "statements" in doc
    return doc


def _vex_cves(doc):
    """The set of CVE ids carried by a VEX document's statements."""
    return {s["vulnerability"]["name"] for s in doc["statements"]}


def test_dump_vex_is_listed_as_supported_format():
    assert "vex" in dump.SUPPORTED_FORMATS


def test_dump_vex_rejected_format_still_errors(db_path):
    db.init_db(db_path).close()
    with pytest.raises(ValueError, match="unsupported dump format"):
        dump.dump(db_path, "yaml")


def test_dump_vex_is_valid_openvex_document(db_path):
    _seed_one_finding(db_path)
    doc = _vex(dump.dump(db_path, "vex"))
    # One statement per finding.
    assert len(doc["statements"]) == 1
    stmt = doc["statements"][0]
    assert stmt["vulnerability"]["name"] == "CVE-2021-23017"
    assert stmt["status"] == "affected"


def test_dump_vex_empty_db_has_empty_statements(db_path):
    db.init_db(db_path).close()
    doc = _vex(dump.dump(db_path, "vex"))
    assert doc["statements"] == []


def test_dump_vex_statement_products_locate_the_finding(db_path):
    _seed_one_finding(db_path)  # nginx 1.18.0 cpe:/a:nginx on 10.10.0.5:tcp/80
    doc = _vex(dump.dump(db_path, "vex"))
    products = doc["statements"][0]["products"]
    assert len(products) == 1
    product = products[0]
    assert product["@id"] == "10.10.0.5:tcp/80"
    assert product["identifiers"]["cpe"] == "cpe:/a:nginx"


def test_dump_vex_product_omits_cpe_when_service_has_none(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, sid, "CVE-2021-23017", "x", "7.7")
        conn.commit()
    finally:
        conn.close()
    doc = _vex(dump.dump(db_path, "vex"))
    product = doc["statements"][0]["products"][0]
    assert product["@id"] == "10.10.0.5:tcp/80"
    assert "identifiers" not in product


def test_dump_vex_statement_carries_summary_as_status_notes(db_path):
    _seed_one_finding(db_path)  # summary "off-by-one"
    doc = _vex(dump.dump(db_path, "vex"))
    assert doc["statements"][0]["status_notes"] == "off-by-one"


def test_dump_vex_one_statement_per_finding(db_path):
    _seed_mixed_findings(db_path)  # 3 findings across 2 services
    doc = _vex(dump.dump(db_path, "vex"))
    assert len(doc["statements"]) == 3
    assert _vex_cves(doc) == {"CVE-HOT", "CVE-COLD", "CVE-MID"}


def test_dump_vex_omits_service_with_no_findings(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.9", None, "up")
        db.upsert_service(conn, aid, 22, "tcp", "ssh", "OpenSSH", "8.2", None)
        conn.commit()
    finally:
        conn.close()
    # VEX is a per-vulnerability ruling list (like SARIF): a service with no
    # finding contributes no statement.
    doc = _vex(dump.dump(db_path, "vex"))
    assert doc["statements"] == []


def test_dump_vex_filters_apply(db_path):
    _seed_mixed_findings(db_path)
    doc = _vex(dump.dump(db_path, "vex", kev_only=True))
    # Only the KEV finding produces a statement.
    assert _vex_cves(doc) == {"CVE-HOT"}


def test_dump_vex_honours_tag_scope(db_path):
    _seed_mixed_findings(db_path)  # all on 10.10.0.5
    conn = db.init_db(db_path)
    try:
        db.upsert_asset(conn, "10.10.0.9", "other", "up")
        aid = conn.execute(
            "SELECT id FROM assets WHERE ip = '10.10.0.9'"
        ).fetchone()["id"]
        sid = db.upsert_service(conn, aid, 21, "tcp", "ftp", "vsftpd", "3.0", None)
        db.upsert_finding(conn, sid, "CVE-FTP", "x", "5.0")
        conn.commit()
    finally:
        conn.close()
    tags.add_tag(db_path, "10.10.0.5", "in-scope")
    doc = _vex(dump.dump(db_path, "vex", tag="in-scope"))
    # The untagged ftp host's finding is excluded.
    assert "CVE-FTP" not in _vex_cves(doc)
    assert _vex_cves(doc) == {"CVE-HOT", "CVE-COLD", "CVE-MID"}


def test_dump_vex_sort_by_priority_orders_statements(db_path):
    _seed_one_service_many_findings(db_path)
    doc = _vex(dump.dump(db_path, "vex", sort_by_priority=True))
    order = [s["vulnerability"]["name"] for s in doc["statements"]]
    assert order == [
        "CVE-2020-KEVHI",
        "CVE-2020-KEVLO",
        "CVE-2020-WARM",
        "CVE-2020-COLD",
    ]


def test_dump_vex_round_trips_through_the_import_parser(db_path):
    # The exported document must parse back through ossuary.vex (the import
    # path), so a hunter can edit it and feed it to `dump --vex`. As exported,
    # every statement is `affected` (un-triaged), which the parser accepts but
    # treats as no suppression — nothing is cleared yet.
    from ossuary import vex as vex_mod

    _seed_mixed_findings(db_path)
    doc = json.loads(dump.dump(db_path, "vex"))
    suppressions = vex_mod.parse(doc)
    assert len(suppressions) == 0  # affected statements suppress nothing

    # Flip one statement to a clearing status, as a triaging hunter would, and
    # re-parse: the cleared CVE is now suppressed for its product location.
    hot = next(s for s in doc["statements"] if s["vulnerability"]["name"] == "CVE-HOT")
    hot["status"] = "not_affected"
    suppressions = vex_mod.parse(doc)
    assert suppressions.is_suppressed(
        "CVE-HOT", identifiers={"10.10.0.5:tcp/80"}
    )
    # And feeding the edited document back into a dump suppresses that row.
    import json as _json
    edited = tmp_vex_file(db_path, doc, _json)
    state = _json.loads(dump.dump(db_path, "json", vex_path=edited))
    remaining = {
        f["cve_id"]
        for a in state["assets"]
        for s in a["services"]
        for f in s["findings"]
    }
    assert "CVE-HOT" not in remaining
    assert "CVE-COLD" in remaining


def tmp_vex_file(db_path, doc, json_mod):
    """Write a VEX doc next to the test DB and return its path (helper)."""
    path = db_path.parent / "edited.vex.json"
    path.write_text(json_mod.dumps(doc), encoding="utf-8")
    return str(path)


# --------------------------------------------------------------------------
# CycloneDX VEX export (`--format cdx-vex`) — the CycloneDX-native VEX shape
# --------------------------------------------------------------------------
#
# A CycloneDX 1.5 document that carries the same components + vulnerabilities
# as `--format cyclonedx` *plus* an `analysis` block on every vulnerability
# whose `state` is the CycloneDX VEX status. Default emitted state is the spec
# value `in_triage` — the editable triage worksheet a hunter ships into a
# Dependency-Track / Anchore / CycloneDX-consuming pipeline alongside the SBOM.

# Valid CycloneDX VEX `analysis.state` values — the spec vocabulary a hunter
# may flip an entry to as they triage.
_CDX_VEX_STATES = {
    "resolved",
    "resolved_with_pedigree",
    "exploitable",
    "in_triage",
    "false_positive",
    "not_affected",
}


def _cdx_vex(out):
    """Parse a CycloneDX-VEX dump and assert its document-level invariants."""
    doc = json.loads(out)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert "components" in doc
    assert "vulnerabilities" in doc
    return doc


def test_dump_cdx_vex_is_listed_as_supported_format():
    assert "cdx-vex" in dump.SUPPORTED_FORMATS


def test_dump_cdx_vex_is_valid_1_5_document(db_path):
    _seed_one_finding(db_path)
    doc = _cdx_vex(dump.dump(db_path, "cdx-vex"))
    tool = doc["metadata"]["tools"][0]
    assert tool["name"] == "ossuary"
    assert "version" in tool
    # Same per-service / per-finding emission as the plain CycloneDX SBOM.
    assert len(doc["components"]) == 1
    assert len(doc["vulnerabilities"]) == 1


def test_dump_cdx_vex_empty_db_has_empty_arrays(db_path):
    db.init_db(db_path).close()
    doc = _cdx_vex(dump.dump(db_path, "cdx-vex"))
    assert doc["components"] == []
    assert doc["vulnerabilities"] == []


def test_dump_cdx_vex_every_vulnerability_carries_analysis_block(db_path):
    _seed_mixed_findings(db_path)
    doc = _cdx_vex(dump.dump(db_path, "cdx-vex"))
    assert len(doc["vulnerabilities"]) >= 1
    for v in doc["vulnerabilities"]:
        # The presence of the `analysis` block is what makes this a VEX
        # document and distinguishes it from a plain CycloneDX SBOM.
        assert "analysis" in v, f"missing analysis on {v.get('id')}"
        assert v["analysis"]["state"] in _CDX_VEX_STATES


def test_dump_cdx_vex_default_state_is_in_triage(db_path):
    _seed_one_finding(db_path)
    doc = _cdx_vex(dump.dump(db_path, "cdx-vex"))
    # Default state on export — every finding is un-triaged; the hunter flips
    # entries to not_affected / false_positive / resolved as they rule out.
    assert doc["vulnerabilities"][0]["analysis"]["state"] == "in_triage"


def test_dump_cdx_vex_carries_same_sbom_fields_as_cyclonedx(db_path):
    """cdx-vex is cyclonedx + analysis — strip analysis and the rest must match."""
    _seed_mixed_findings(db_path)
    sbom = json.loads(dump.dump(db_path, "cyclonedx"))
    vex = json.loads(dump.dump(db_path, "cdx-vex"))
    assert sbom["components"] == vex["components"]
    stripped = [
        {k: val for k, val in v.items() if k != "analysis"}
        for v in vex["vulnerabilities"]
    ]
    assert stripped == sbom["vulnerabilities"]


def test_dump_cdx_vex_vulnerability_still_links_to_component(db_path):
    """The SBOM linkage (affects[].ref) survives the VEX overlay."""
    _seed_one_finding(db_path)
    doc = _cdx_vex(dump.dump(db_path, "cdx-vex"))
    comp_ref = doc["components"][0]["bom-ref"]
    vuln = doc["vulnerabilities"][0]
    assert vuln["id"] == "CVE-2021-23017"
    assert vuln["affects"][0]["ref"] == comp_ref


def test_dump_cdx_vex_emits_component_even_with_no_findings(db_path):
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.9", None, "up")
        db.upsert_service(conn, aid, 22, "tcp", "ssh", "OpenSSH", "8.2", None)
        conn.commit()
    finally:
        conn.close()
    doc = _cdx_vex(dump.dump(db_path, "cdx-vex"))
    assert len(doc["components"]) == 1
    assert doc["components"][0]["name"] == "OpenSSH"
    assert doc["vulnerabilities"] == []


def test_dump_cdx_vex_filters_apply(db_path):
    _seed_mixed_findings(db_path)
    doc = _cdx_vex(dump.dump(db_path, "cdx-vex", kev_only=True))
    cves = {v["id"] for v in doc["vulnerabilities"]}
    assert cves == {"CVE-HOT"}
    # And the surviving vuln still carries its analysis block.
    assert doc["vulnerabilities"][0]["analysis"]["state"] == "in_triage"


def test_dump_cdx_vex_sort_by_priority_orders_vulnerabilities(db_path):
    _seed_one_service_many_findings(db_path)
    doc = _cdx_vex(dump.dump(db_path, "cdx-vex", sort_by_priority=True))
    emitted = [v["id"] for v in doc["vulnerabilities"]]
    assert emitted == [
        "CVE-2020-KEVHI",
        "CVE-2020-KEVLO",
        "CVE-2020-WARM",
        "CVE-2020-COLD",
    ]


def test_dump_cdx_vex_tag_filter_applies(db_path):
    """The `--tag` scope composes with the cdx-vex export like every other format."""
    conn = db.init_db(db_path)
    try:
        a1 = db.upsert_asset(conn, "10.10.0.5", "h1", "up")
        s1 = db.upsert_service(conn, a1, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, s1, "CVE-IN", "x", "7.0")
        a2 = db.upsert_asset(conn, "10.10.0.6", "h2", "up")
        s2 = db.upsert_service(conn, a2, 80, "tcp", "http", "nginx", "1.0", None)
        db.upsert_finding(conn, s2, "CVE-OUT", "x", "7.0")
        conn.commit()
    finally:
        conn.close()
    tags.add_tag(db_path, "10.10.0.5", "prod")
    doc = _cdx_vex(dump.dump(db_path, "cdx-vex", tag="prod"))
    cves = {v["id"] for v in doc["vulnerabilities"]}
    assert cves == {"CVE-IN"}
    assert {c["bom-ref"] for c in doc["components"]} == {"10.10.0.5:tcp/80"}


def test_dump_cdx_vex_vex_suppression_applies(db_path):
    """A `--vex` suppression is applied upstream of the cdx-vex emission."""
    _seed_mixed_findings(db_path)
    # Author an OpenVEX doc that rules CVE-HOT not_affected on its location.
    vex_doc = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://example.test/vex/suppress-hot",
        "author": "test",
        "timestamp": "1970-01-01T00:00:00Z",
        "version": 1,
        "statements": [
            {
                "vulnerability": {"name": "CVE-HOT"},
                "status": "not_affected",
                "products": [{"@id": "10.10.0.5:tcp/80"}],
            }
        ],
    }
    suppress_path = tmp_vex_file(db_path, vex_doc, json)
    doc = _cdx_vex(dump.dump(db_path, "cdx-vex", vex_path=suppress_path))
    cves = {v["id"] for v in doc["vulnerabilities"]}
    assert "CVE-HOT" not in cves
    # And remaining entries still carry the analysis block.
    for v in doc["vulnerabilities"]:
        assert v["analysis"]["state"] == "in_triage"


def test_dump_cdx_vex_round_trip_through_json_parse(db_path):
    """The emitted document is valid JSON and stable across two emissions."""
    _seed_one_finding(db_path)
    first = dump.dump(db_path, "cdx-vex")
    second = dump.dump(db_path, "cdx-vex")
    assert first == second
    doc = json.loads(first)
    # Indented (human-readable) like the other JSON formats.
    assert "\n" in first
    assert doc["bomFormat"] == "CycloneDX"
