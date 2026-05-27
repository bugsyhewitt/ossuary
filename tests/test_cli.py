"""CLI smoke tests (criteria 2, 9). Exercises the full pipeline with all
network seams mocked — no live nmap, no live OSV.dev.
"""

from __future__ import annotations

import json
import sqlite3

import pytest
from conftest import (
    TARGETS_FILE,
    host_discovery_result,
    osv_response,
    service_scan_result,
)

from ossuary import cli, cves, discover, enrich, fingerprint


def test_help_lists_all_subcommands(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    out = capsys.readouterr().out
    for sub in ("init", "discover", "fingerprint", "match-cves", "cruise", "dump"):
        assert sub in out


def test_no_command_errors_cleanly(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code != 0


def test_version_flag(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    out = capsys.readouterr().out
    assert "ossuary" in out


def test_subcommand_against_uninitialised_db_returns_error(tmp_path, capsys):
    rc = cli.main(["dump", "--db", str(tmp_path / "missing.db")])
    assert rc == 1
    err = capsys.readouterr().err
    assert "not initialised" in err


def test_full_pipeline_offline(tmp_path, monkeypatch, capsys):
    """init -> discover -> fingerprint -> match-cves -> dump, all mocked."""
    db_file = str(tmp_path / "engagement-test.db")

    # ---- mock all network seams ----
    monkeypatch.setattr(
        discover,
        "scan_hosts",
        lambda targets: host_discovery_result(up_ips=["10.10.0.5", "10.10.0.6"]),
    )
    monkeypatch.setattr(
        fingerprint,
        "scan_services",
        lambda ip: service_scan_result(
            ip, [{"port": 80, "name": "http", "product": "nginx", "version": "1.18.0"}]
        ),
    )
    monkeypatch.setattr(
        cves,
        "query_osv",
        lambda product, version: osv_response(
            [{"id": "GHSA-x", "aliases": ["CVE-2021-23017"], "summary": "x", "severity": []}]
        ),
    )
    # match-cves enriches by default; mock those seams to keep the suite offline.
    monkeypatch.setattr(enrich, "query_epss", lambda cve_id: 0.42)
    monkeypatch.setattr(
        enrich, "fetch_kev_catalog",
        lambda: {"vulnerabilities": [{"cveID": "CVE-2021-23017"}]},
    )

    assert cli.main(["init", "--db", db_file]) == 0
    assert cli.main(["discover", "--db", db_file, "--targets", str(TARGETS_FILE)]) == 0
    assert cli.main(["fingerprint", "--db", db_file]) == 0
    assert cli.main(["match-cves", "--db", db_file]) == 0

    capsys.readouterr()  # clear buffered output
    assert cli.main(["dump", "--db", db_file, "--format", "json"]) == 0
    out = capsys.readouterr().out
    state = json.loads(out)

    assert len(state["assets"]) == 2
    nginx_finding = state["assets"][0]["services"][0]["findings"][0]
    assert nginx_finding["cve_id"] == "CVE-2021-23017"
    # enrichment fields surface in the dump
    assert nginx_finding["epss_score"] == 0.42
    assert nginx_finding["kev"] == 1


def _seed_match_pipeline(tmp_path, monkeypatch):
    """init -> discover -> fingerprint, with one nginx service ready to match."""
    db_file = str(tmp_path / "engagement-test.db")
    monkeypatch.setattr(
        discover,
        "scan_hosts",
        lambda targets: host_discovery_result(up_ips=["10.10.0.5"]),
    )
    monkeypatch.setattr(
        fingerprint,
        "scan_services",
        lambda ip: service_scan_result(
            ip, [{"port": 80, "name": "http", "product": "nginx", "version": "1.18.0"}]
        ),
    )
    monkeypatch.setattr(
        cves,
        "query_osv",
        lambda product, version: osv_response(
            [{"id": "GHSA-x", "aliases": ["CVE-2021-23017"], "summary": "x",
              "severity": []}]
        ),
    )
    cli.main(["init", "--db", db_file])
    cli.main(["discover", "--db", db_file, "--targets", str(TARGETS_FILE)])
    cli.main(["fingerprint", "--db", db_file])
    return db_file


def test_match_cves_default_enriches_and_displays(tmp_path, monkeypatch, capsys):
    db_file = _seed_match_pipeline(tmp_path, monkeypatch)
    monkeypatch.setattr(enrich, "query_epss", lambda cve_id: 0.87)
    monkeypatch.setattr(
        enrich, "fetch_kev_catalog",
        lambda: {"vulnerabilities": [{"cveID": "CVE-2021-23017"}]},
    )

    capsys.readouterr()
    rc = cli.main(["match-cves", "--db", db_file])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CVE-2021-23017" in out
    assert "EPSS: 0.87" in out
    assert "KEV: YES" in out


def test_match_cves_no_enrich_makes_no_enrichment_calls(tmp_path, monkeypatch, capsys):
    db_file = _seed_match_pipeline(tmp_path, monkeypatch)

    def boom(*a, **k):  # pragma: no cover - must not be called
        raise AssertionError("enrichment must not run under --no-enrich")

    monkeypatch.setattr(enrich, "query_epss", boom)
    monkeypatch.setattr(enrich, "fetch_kev_catalog", boom)

    capsys.readouterr()
    rc = cli.main(["match-cves", "--db", db_file, "--no-enrich"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CVE-2021-23017" in out
    assert "EPSS: —" in out
    assert "KEV: no" in out


def test_match_cves_source_both_queries_nvd(tmp_path, monkeypatch, capsys):
    db_file = _seed_match_pipeline(tmp_path, monkeypatch)
    monkeypatch.setattr(cves.time, "sleep", lambda _s: None)

    nvd_calls: list[str | None] = []

    def fake_query_nvd(cpe, product, api_key=None):
        nvd_calls.append(api_key)
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2019-9511",
                        "descriptions": [{"lang": "en", "value": "HTTP/2 flood"}],
                    }
                }
            ]
        }

    monkeypatch.setattr(cves, "query_nvd", fake_query_nvd)

    capsys.readouterr()
    rc = cli.main(
        ["match-cves", "--db", db_file, "--no-enrich", "--source", "both"]
    )
    assert rc == 0
    out = capsys.readouterr().out
    # OSV's CVE and the NVD-only CVE both surface under --source both.
    assert "CVE-2021-23017" in out
    assert "CVE-2019-9511" in out
    assert nvd_calls == [None]


def test_cli_cruise_runs_and_exits_zero(tmp_path, monkeypatch, capsys):
    db_file = str(tmp_path / "engagement-test.db")
    monkeypatch.setattr(
        discover,
        "scan_hosts",
        lambda targets: host_discovery_result(up_ips=["10.10.0.5"]),
    )
    monkeypatch.setattr(
        fingerprint,
        "scan_services",
        lambda ip: service_scan_result(
            ip, [{"port": 22, "name": "ssh", "product": "OpenSSH", "version": "8.9p1"}]
        ),
    )
    cli.main(["init", "--db", db_file])
    cli.main(["discover", "--db", db_file, "--targets", str(TARGETS_FILE)])
    capsys.readouterr()

    rc = cli.main(["cruise", "--db", db_file])
    assert rc == 0
    out = capsys.readouterr().out
    assert "cruise diff" in out
    diff = json.loads(out[out.index("{") :])
    assert len(diff["added"]) == 1
