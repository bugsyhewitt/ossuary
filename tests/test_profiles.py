"""Tests for named scan profiles (POST_V01 #7).

Covers the profiles module, the recording of the chosen profile on asset /
service rows by discover & fingerprint, the cruise `profile_changes` diff that
flags a service re-scanned under a different profile, and the CLI wiring
(`--profile` flag + `ossuary profiles` listing). All nmap shell-outs are
mocked so no live scan runs; the seams additionally assert that the profile's
nmap flags are threaded down to the network layer.
"""

from __future__ import annotations

import sqlite3

import pytest
from conftest import TARGETS_FILE, host_discovery_result, service_scan_result

from ossuary import cli, cruise, db, discover, fingerprint, profiles


# --------------------------------------------------------------------------
# profiles module
# --------------------------------------------------------------------------

def test_default_profile_reproduces_original_flags():
    prof = profiles.get_profile(profiles.DEFAULT_PROFILE)
    assert prof.name == "default"
    assert prof.discover == "-sn"
    assert prof.fingerprint == "-sV"


def test_named_profiles_present_with_distinct_flags():
    names = profiles.profile_names()
    assert names[0] == profiles.DEFAULT_PROFILE  # default presented first
    for expected in ("stealth", "aggressive", "web"):
        assert expected in names
    stealth = profiles.get_profile("stealth")
    aggressive = profiles.get_profile("aggressive")
    web = profiles.get_profile("web")
    # Each carries its own intent-specific fingerprint flag string.
    assert "-Pn" in stealth.fingerprint
    assert "-O" in aggressive.fingerprint
    assert "80,443" in web.fingerprint


def test_unknown_profile_raises_with_helpful_message():
    with pytest.raises(ValueError, match="unknown scan profile 'bogus'"):
        profiles.get_profile("bogus")


def test_list_profiles_returns_every_profile():
    assert len(profiles.list_profiles()) == len(profiles.profile_names())


# --------------------------------------------------------------------------
# discover / fingerprint record the chosen profile (and use its flags)
# --------------------------------------------------------------------------

def test_discover_threads_profile_flags_and_records_name(db_path, monkeypatch):
    db.init_db(db_path).close()
    seen = {}

    def fake_scan_hosts(targets, arguments="-sn"):
        seen["arguments"] = arguments
        return host_discovery_result(up_ips=["10.10.0.5"])

    monkeypatch.setattr(discover, "scan_hosts", fake_scan_hosts)

    count = discover.discover(db_path, TARGETS_FILE, profile="stealth")
    assert count == 1
    # The stealth profile's discover flags reached the nmap seam.
    assert seen["arguments"] == profiles.get_profile("stealth").discover

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT scan_profile FROM assets WHERE ip = '10.10.0.5'"
        ).fetchone()
    finally:
        conn.close()
    assert row["scan_profile"] == "stealth"


def test_fingerprint_threads_profile_flags_and_records_name(db_path, monkeypatch):
    conn = db.init_db(db_path)
    db.upsert_asset(conn, "10.10.0.5", None, "up")
    conn.commit()
    conn.close()

    seen = {}

    def fake_scan_services(ip, arguments="-sV"):
        seen["arguments"] = arguments
        return service_scan_result(
            ip, [{"port": 80, "name": "http", "product": "nginx", "version": "1.18.0"}]
        )

    monkeypatch.setattr(fingerprint, "scan_services", fake_scan_services)

    count = fingerprint.fingerprint(db_path, profile="web")
    assert count == 1
    assert seen["arguments"] == profiles.get_profile("web").fingerprint

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT scan_profile FROM services").fetchone()
    finally:
        conn.close()
    assert row["scan_profile"] == "web"


def test_default_profile_is_recorded_when_unspecified(db_path, monkeypatch):
    db.init_db(db_path).close()
    monkeypatch.setattr(
        discover,
        "scan_hosts",
        lambda t, arguments="-sn": host_discovery_result(up_ips=["10.10.0.5"]),
    )
    discover.discover(db_path, TARGETS_FILE)  # no profile passed
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT scan_profile FROM assets").fetchone()
    finally:
        conn.close()
    assert row["scan_profile"] == "default"


# --------------------------------------------------------------------------
# cruise flags a profile mismatch between successive scans
# --------------------------------------------------------------------------

def test_diff_snapshots_flags_profile_change():
    prev = {
        "10.10.0.5:tcp/80": {
            "name": "http", "product": "nginx", "version": "1.18.0",
            "scan_profile": "default",
        }
    }
    cur = {
        "10.10.0.5:tcp/80": {
            "name": "http", "product": "nginx", "version": "1.18.0",
            "scan_profile": "web",
        }
    }
    diff = cruise.diff_snapshots(prev, cur)
    assert diff["profile_changes"] == [
        {"service": "10.10.0.5:tcp/80", "from": "default", "to": "web"}
    ]


def test_diff_snapshots_no_profile_change_when_same():
    snap = {
        "10.10.0.5:tcp/80": {
            "name": "http", "product": "nginx", "version": "1.18.0",
            "scan_profile": "default",
        }
    }
    diff = cruise.diff_snapshots(dict(snap), dict(snap))
    assert diff["profile_changes"] == []


def test_diff_snapshots_treats_missing_profile_as_default():
    # An older snapshot row predating the column omits scan_profile entirely.
    prev = {"10.10.0.5:tcp/80": {"name": "http", "product": "nginx", "version": "1.18.0"}}
    cur = {
        "10.10.0.5:tcp/80": {
            "name": "http", "product": "nginx", "version": "1.18.0",
            "scan_profile": "default",
        }
    }
    diff = cruise.diff_snapshots(prev, cur)
    assert diff["profile_changes"] == []


def test_cruise_reports_profile_change_end_to_end(db_path, monkeypatch):
    conn = db.init_db(db_path)
    db.upsert_asset(conn, "10.10.0.5", None, "up")
    conn.commit()
    conn.close()

    monkeypatch.setattr(
        fingerprint,
        "scan_services",
        lambda ip, arguments="-sV": service_scan_result(
            ip, [{"port": 80, "name": "http", "product": "nginx", "version": "1.18.0"}]
        ),
    )

    # First cruise under default establishes the baseline.
    first = cruise.cruise(db_path)
    assert first["profile_changes"] == []

    # Second cruise under the web profile flags the mismatch on the same service.
    second = cruise.cruise(db_path, profile="web")
    assert second["profile_changes"] == [
        {"service": "10.10.0.5:tcp/80", "from": "default", "to": "web"}
    ]
    # The service itself is otherwise unchanged (no spurious version diff).
    assert second["changed"][0]["from"]["scan_profile"] == "default"
    assert second["changed"][0]["to"]["scan_profile"] == "web"


# --------------------------------------------------------------------------
# CLI wiring
# --------------------------------------------------------------------------

def test_cli_profiles_lists_all_profiles(capsys):
    rc = cli.main(["profiles"])
    assert rc == 0
    out = capsys.readouterr().out
    for name in ("default", "stealth", "aggressive", "web"):
        assert name in out
    assert "nmap" in out  # flag strings shown


def test_cli_rejects_unknown_profile(capsys):
    with pytest.raises(SystemExit):
        cli.main(["fingerprint", "--db", "x.db", "--profile", "bogus"])
    err = capsys.readouterr().err
    assert "bogus" in err or "invalid choice" in err


def test_cli_discover_passes_profile_through(tmp_path, monkeypatch, capsys):
    db_file = str(tmp_path / "engagement-test.db")
    seen = {}

    def fake_scan_hosts(targets, arguments="-sn"):
        seen["arguments"] = arguments
        return host_discovery_result(up_ips=["10.10.0.5"])

    monkeypatch.setattr(discover, "scan_hosts", fake_scan_hosts)

    cli.main(["init", "--db", db_file])
    rc = cli.main(
        ["discover", "--db", db_file, "--targets", str(TARGETS_FILE), "--profile", "stealth"]
    )
    assert rc == 0
    assert seen["arguments"] == profiles.get_profile("stealth").discover
    out = capsys.readouterr().out
    assert "profile: stealth" in out
