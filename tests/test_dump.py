"""Tests for JSON export (criterion 7) and CSV/Markdown export (POST_V01 #6)."""

from __future__ import annotations

import csv
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
