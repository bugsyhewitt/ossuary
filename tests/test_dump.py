"""Tests for JSON export (criterion 7) and CSV/Markdown export (POST_V01 #6)."""

from __future__ import annotations

import csv
import html
import io
import json

import pytest

from ossuary import db, dump

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
