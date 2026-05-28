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
