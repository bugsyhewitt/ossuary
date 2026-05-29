"""Tests for the finding-level diff command (`ossuary diff`).

`diff` compares the findings of two engagement DB files — a baseline (earlier
scan) and a current one (later scan) — and classifies every distinct finding,
keyed on (ip:proto/port, cve_id), as new / resolved / persisting. It reads each
DB through `dump.build_state`, so it honours the same actionability filters as
the rest of the suite. No network, no new schema.
"""

from __future__ import annotations

import json

import pytest

from ossuary import cli, db, findingdiff


# --------------------------------------------------------------------------
# Seed helpers — two engagement DBs with overlapping but differing findings.
# --------------------------------------------------------------------------

def _seed(db_path, findings):
    """Build an engagement DB with one asset and the given findings.

    `findings` is a list of (port, product, version, cve_id, severity, epss,
    kev) tuples. All hang off a single asset 10.10.0.5 / host-a so the location
    key is driven purely by port + cve_id.
    """
    conn = db.init_db(db_path)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        svc_ids: dict[int, int] = {}
        for port, product, version, cve_id, severity, epss, kev in findings:
            if port not in svc_ids:
                svc_ids[port] = db.upsert_service(
                    conn, aid, port, "tcp", "svc", product, version, None
                )
            db.upsert_finding(
                conn,
                svc_ids[port],
                cve_id,
                f"summary for {cve_id}",
                severity,
                epss_score=epss,
                kev=kev,
            )
        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def baseline_db(tmp_path):
    """Baseline scan: nginx 1.18.0 on :80 with two CVEs."""
    path = tmp_path / "baseline.db"
    _seed(
        path,
        [
            (80, "nginx", "1.18.0", "CVE-OLD-1", "7.5", 0.40, 0),
            (80, "nginx", "1.18.0", "CVE-PATCHED", "9.1", 0.80, 1),
            (22, "OpenSSH", "8.2", "CVE-SSH", "5.0", 0.05, 0),
        ],
    )
    return path


@pytest.fixture
def current_db(tmp_path):
    """Current scan: nginx bumped to 1.24.0 — CVE-PATCHED gone, a new CVE seen."""
    path = tmp_path / "current.db"
    _seed(
        path,
        [
            (80, "nginx", "1.24.0", "CVE-OLD-1", "7.5", 0.40, 0),  # persisting
            (80, "nginx", "1.24.0", "CVE-NEW-1", "8.8", 0.90, 1),  # new
            (22, "OpenSSH", "8.2", "CVE-SSH", "5.0", 0.05, 0),     # persisting
        ],
    )
    return path


# --------------------------------------------------------------------------
# diff_states / build_diff — core classification
# --------------------------------------------------------------------------

def test_build_diff_classifies_new(baseline_db, current_db):
    result = findingdiff.build_diff(baseline_db, current_db)
    new_ids = {e["cve_id"] for e in result["new"]}
    assert new_ids == {"CVE-NEW-1"}


def test_build_diff_classifies_resolved(baseline_db, current_db):
    result = findingdiff.build_diff(baseline_db, current_db)
    resolved_ids = {e["cve_id"] for e in result["resolved"]}
    assert resolved_ids == {"CVE-PATCHED"}


def test_build_diff_classifies_persisting(baseline_db, current_db):
    result = findingdiff.build_diff(baseline_db, current_db)
    persisting_ids = {e["cve_id"] for e in result["persisting"]}
    assert persisting_ids == {"CVE-OLD-1", "CVE-SSH"}


def test_new_entry_carries_current_detail(baseline_db, current_db):
    result = findingdiff.build_diff(baseline_db, current_db)
    entry = next(e for e in result["new"] if e["cve_id"] == "CVE-NEW-1")
    assert entry["location"] == "10.10.0.5:tcp/80"
    assert entry["version"] == "1.24.0"
    assert entry["severity"] == "8.8"
    assert entry["epss_score"] == 0.90
    assert entry["kev"] == 1


def test_resolved_entry_carries_baseline_detail(baseline_db, current_db):
    result = findingdiff.build_diff(baseline_db, current_db)
    entry = next(e for e in result["resolved"] if e["cve_id"] == "CVE-PATCHED")
    # The current DB no longer has it; the baseline's version is reported.
    assert entry["version"] == "1.18.0"
    assert entry["kev"] == 1


def test_persisting_entry_uses_current_detail(baseline_db, current_db):
    # CVE-OLD-1's owning service version changed 1.18.0 -> 1.24.0; the persisting
    # entry should report the *current* version (the live state).
    result = findingdiff.build_diff(baseline_db, current_db)
    entry = next(e for e in result["persisting"] if e["cve_id"] == "CVE-OLD-1")
    assert entry["version"] == "1.24.0"


def test_identical_dbs_have_no_changes(baseline_db, tmp_path):
    # Diff a DB against a byte-identical copy of its findings.
    copy = tmp_path / "copy.db"
    _seed(
        copy,
        [
            (80, "nginx", "1.18.0", "CVE-OLD-1", "7.5", 0.40, 0),
            (80, "nginx", "1.18.0", "CVE-PATCHED", "9.1", 0.80, 1),
            (22, "OpenSSH", "8.2", "CVE-SSH", "5.0", 0.05, 0),
        ],
    )
    result = findingdiff.build_diff(baseline_db, copy)
    assert result["new"] == []
    assert result["resolved"] == []
    assert len(result["persisting"]) == 3


def test_diff_is_directional(baseline_db, current_db):
    # Swapping baseline and current swaps new <-> resolved.
    forward = findingdiff.build_diff(baseline_db, current_db)
    backward = findingdiff.build_diff(current_db, baseline_db)
    assert {e["cve_id"] for e in forward["new"]} == {
        e["cve_id"] for e in backward["resolved"]
    }
    assert {e["cve_id"] for e in forward["resolved"]} == {
        e["cve_id"] for e in backward["new"]
    }


# --------------------------------------------------------------------------
# Location keying — same CVE on a different port is a distinct finding.
# --------------------------------------------------------------------------

def test_same_cve_moving_ports_counts_as_resolved_plus_new(tmp_path):
    base = tmp_path / "b.db"
    cur = tmp_path / "c.db"
    _seed(base, [(80, "app", "1.0", "CVE-MOVE", "7.0", 0.5, 0)])
    _seed(cur, [(8080, "app", "1.0", "CVE-MOVE", "7.0", 0.5, 0)])
    result = findingdiff.build_diff(base, cur)
    assert [e["location"] for e in result["new"]] == ["10.10.0.5:tcp/8080"]
    assert [e["location"] for e in result["resolved"]] == ["10.10.0.5:tcp/80"]
    assert result["persisting"] == []


def test_entries_sorted_by_location_then_cve(tmp_path):
    base = tmp_path / "b.db"
    cur = tmp_path / "c.db"
    _seed(base, [])
    _seed(
        cur,
        [
            (443, "x", "1", "CVE-B", "5", 0.1, 0),
            (80, "y", "1", "CVE-Z", "5", 0.1, 0),
            (80, "y", "1", "CVE-A", "5", 0.1, 0),
        ],
    )
    result = findingdiff.build_diff(base, cur)
    keys = [(e["location"], e["cve_id"]) for e in result["new"]]
    assert keys == [
        ("10.10.0.5:tcp/443", "CVE-B"),
        ("10.10.0.5:tcp/80", "CVE-A"),
        ("10.10.0.5:tcp/80", "CVE-Z"),
    ]


# --------------------------------------------------------------------------
# Actionability filters — scope both sides before diffing.
# --------------------------------------------------------------------------

def test_kev_only_scopes_both_sides(baseline_db, current_db):
    # KEV findings: baseline CVE-PATCHED(kev), current CVE-NEW-1(kev).
    result = findingdiff.build_diff(baseline_db, current_db, kev_only=True)
    assert {e["cve_id"] for e in result["new"]} == {"CVE-NEW-1"}
    assert {e["cve_id"] for e in result["resolved"]} == {"CVE-PATCHED"}
    # CVE-OLD-1 / CVE-SSH are non-KEV, so they drop out of persisting too.
    assert result["persisting"] == []


def test_min_epss_filters_low_scores(baseline_db, current_db):
    # With a 0.85 floor only CVE-NEW-1 (0.90) survives on the current side; on
    # the baseline side CVE-PATCHED (0.80) is below the floor, so nothing
    # resolved clears it.
    result = findingdiff.build_diff(baseline_db, current_db, min_epss=0.85)
    assert {e["cve_id"] for e in result["new"]} == {"CVE-NEW-1"}
    assert result["resolved"] == []


def test_min_severity_filters(baseline_db, current_db):
    result = findingdiff.build_diff(baseline_db, current_db, min_severity=8.0)
    # current >=8.0: CVE-NEW-1 (8.8). baseline >=8.0: CVE-PATCHED (9.1).
    assert {e["cve_id"] for e in result["new"]} == {"CVE-NEW-1"}
    assert {e["cve_id"] for e in result["resolved"]} == {"CVE-PATCHED"}


# --------------------------------------------------------------------------
# Serialisation — text and json.
# --------------------------------------------------------------------------

def test_diff_json_round_trips(baseline_db, current_db):
    out = findingdiff.diff(baseline_db, current_db, "json")
    parsed = json.loads(out)
    assert set(parsed) == {"new", "resolved", "persisting"}
    assert {e["cve_id"] for e in parsed["new"]} == {"CVE-NEW-1"}


def test_diff_text_has_count_header(baseline_db, current_db):
    out = findingdiff.diff(baseline_db, current_db, "text")
    assert "finding diff: 1 new, 1 resolved, 2 persisting" in out


def test_diff_text_lists_new_and_resolved(baseline_db, current_db):
    out = findingdiff.diff(baseline_db, current_db, "text")
    assert "CVE-NEW-1" in out
    assert "CVE-PATCHED" in out
    # Persisting findings are counted but not individually listed.
    assert "newly exposed" in out
    assert "patched / removed" in out


def test_diff_text_quiet_when_no_change(baseline_db, tmp_path):
    copy = tmp_path / "copy.db"
    _seed(
        copy,
        [
            (80, "nginx", "1.18.0", "CVE-OLD-1", "7.5", 0.40, 0),
            (80, "nginx", "1.18.0", "CVE-PATCHED", "9.1", 0.80, 1),
            (22, "OpenSSH", "8.2", "CVE-SSH", "5.0", 0.05, 0),
        ],
    )
    out = findingdiff.diff(baseline_db, copy, "text")
    assert "no findings appeared or were resolved" in out


def test_diff_rejects_unknown_format(baseline_db, current_db):
    with pytest.raises(ValueError, match="unsupported diff format"):
        findingdiff.diff(baseline_db, current_db, "xml")


def test_diff_against_uninitialised_db_raises(baseline_db, tmp_path):
    missing = tmp_path / "nope.db"
    with pytest.raises(RuntimeError, match="not initialised"):
        findingdiff.build_diff(baseline_db, missing)


# --------------------------------------------------------------------------
# CLI wiring.
# --------------------------------------------------------------------------

def test_cli_diff_text(baseline_db, current_db, capsys):
    rc = cli.main(
        ["diff", "--db", str(baseline_db), "--against", str(current_db)]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "finding diff: 1 new, 1 resolved, 2 persisting" in out


def test_cli_diff_json(baseline_db, current_db, capsys):
    rc = cli.main(
        [
            "diff",
            "--db",
            str(baseline_db),
            "--against",
            str(current_db),
            "--format",
            "json",
        ]
    )
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert {e["cve_id"] for e in parsed["new"]} == {"CVE-NEW-1"}


def test_cli_diff_kev_only(baseline_db, current_db, capsys):
    rc = cli.main(
        [
            "diff",
            "--db",
            str(baseline_db),
            "--against",
            str(current_db),
            "--kev-only",
            "--format",
            "json",
        ]
    )
    assert rc == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["persisting"] == []
    assert {e["cve_id"] for e in parsed["new"]} == {"CVE-NEW-1"}


def test_cli_diff_missing_db_errors(current_db, tmp_path, capsys):
    rc = cli.main(
        ["diff", "--db", str(tmp_path / "absent.db"), "--against", str(current_db)]
    )
    assert rc == 1
    assert "not initialised" in capsys.readouterr().err
