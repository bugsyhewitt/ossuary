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
    for sub in ("init", "discover", "fingerprint", "match-cves", "cruise", "dump", "stats"):
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
        lambda targets, arguments="-sn": host_discovery_result(
            up_ips=["10.10.0.5", "10.10.0.6"]
        ),
    )
    monkeypatch.setattr(
        fingerprint,
        "scan_services",
        lambda ip, arguments="-sV": service_scan_result(
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
    monkeypatch.setattr(
        enrich, "fetch_exploitdb_index", lambda: "id,codes\n1,CVE-2021-23017\n"
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
        lambda targets, arguments="-sn": host_discovery_result(up_ips=["10.10.0.5"]),
    )
    monkeypatch.setattr(
        fingerprint,
        "scan_services",
        lambda ip, arguments="-sV": service_scan_result(
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
    monkeypatch.setattr(
        enrich, "fetch_exploitdb_index", lambda: "id,codes\n1,CVE-2021-23017\n"
    )

    capsys.readouterr()
    rc = cli.main(["match-cves", "--db", db_file])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CVE-2021-23017" in out
    assert "EPSS: 0.87" in out
    assert "KEV: YES" in out
    # the matched CVE has a public exploit in the (mocked) Exploit-DB index
    assert "Exploit: YES" in out


def test_match_cves_no_enrich_makes_no_enrichment_calls(tmp_path, monkeypatch, capsys):
    db_file = _seed_match_pipeline(tmp_path, monkeypatch)

    def boom(*a, **k):  # pragma: no cover - must not be called
        raise AssertionError("enrichment must not run under --no-enrich")

    monkeypatch.setattr(enrich, "query_epss", boom)
    monkeypatch.setattr(enrich, "fetch_kev_catalog", boom)
    monkeypatch.setattr(enrich, "fetch_exploitdb_index", boom)

    capsys.readouterr()
    rc = cli.main(["match-cves", "--db", db_file, "--no-enrich"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CVE-2021-23017" in out
    assert "EPSS: —" in out
    assert "KEV: no" in out
    assert "Exploit: no" in out


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


def test_match_cves_web_flag_matches_web_probe_banner(tmp_path, monkeypatch, capsys):
    """--web additionally matches versioned web_probes Server banners."""
    import sqlite3

    db_file = _seed_match_pipeline(tmp_path, monkeypatch)

    # Add a web_probes row whose Server banner advertises a versioned product
    # that nmap (port 80, version 1.18.0) did not surface.
    conn = sqlite3.connect(db_file)
    try:
        aid = conn.execute("SELECT id FROM assets LIMIT 1").fetchone()[0]
        conn.execute(
            "INSERT INTO web_probes (asset_id, port, protocol, status_code, "
            "server, tech_fingerprints) VALUES (?, 80, 'http', 200, "
            "'Apache/2.4.49 (Ubuntu)', '[]')",
            (aid,),
        )
        conn.commit()
    finally:
        conn.close()

    web_queries: list[tuple[str, str]] = []

    def fake_query_osv(product, version):
        web_queries.append((product, version))
        # nmap nginx path returns the known CVE; web Apache path returns its own.
        if product == "http_server":
            return osv_response(
                [{"id": "GHSA-y", "aliases": ["CVE-2021-41773"], "summary": "trav",
                  "severity": []}]
            )
        return osv_response(
            [{"id": "GHSA-x", "aliases": ["CVE-2021-23017"], "summary": "x",
              "severity": []}]
        )

    monkeypatch.setattr(cves, "query_osv", fake_query_osv)

    capsys.readouterr()
    rc = cli.main(["match-cves", "--db", db_file, "--no-enrich", "--web"])
    assert rc == 0
    out = capsys.readouterr().out
    # Both the nmap-service CVE and the web-banner CVE are reported.
    assert "CVE-2021-23017" in out  # nmap nginx
    assert "CVE-2021-41773" in out  # web Apache banner
    assert "web finding" in out
    assert ("http_server", "2.4.49") in web_queries


def test_match_cves_without_web_flag_ignores_web_probes(tmp_path, monkeypatch, capsys):
    """Default match-cves (no --web) must not query web_probes banners."""
    import sqlite3

    db_file = _seed_match_pipeline(tmp_path, monkeypatch)
    conn = sqlite3.connect(db_file)
    try:
        aid = conn.execute("SELECT id FROM assets LIMIT 1").fetchone()[0]
        conn.execute(
            "INSERT INTO web_probes (asset_id, port, protocol, status_code, "
            "server, tech_fingerprints) VALUES (?, 80, 'http', 200, "
            "'Apache/2.4.49', '[]')",
            (aid,),
        )
        conn.commit()
    finally:
        conn.close()

    queried_products: list[str] = []
    monkeypatch.setattr(
        cves,
        "query_osv",
        lambda product, version: queried_products.append(product)
        or osv_response([]),
    )

    capsys.readouterr()
    rc = cli.main(["match-cves", "--db", db_file, "--no-enrich"])
    assert rc == 0
    # Only the nmap service product is queried; the Apache web banner is ignored.
    assert "http_server" not in queried_products


def _seed_one_asset_db(tmp_path, monkeypatch):
    """init + discover one asset (10.10.0.5), no fingerprint, returns db path."""
    db_file = str(tmp_path / "engagement-test.db")
    monkeypatch.setattr(
        discover,
        "scan_hosts",
        lambda targets, arguments="-sn": host_discovery_result(up_ips=["10.10.0.5"]),
    )
    cli.main(["init", "--db", db_file])
    cli.main(["discover", "--db", db_file, "--targets", str(TARGETS_FILE)])
    return db_file


def test_help_lists_tag_subcommand(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    out = capsys.readouterr().out
    assert "tag" in out


def test_cli_tag_add_list_rm_roundtrip(tmp_path, monkeypatch, capsys):
    db_file = _seed_one_asset_db(tmp_path, monkeypatch)
    capsys.readouterr()

    rc = cli.main(["tag", "add", "--db", db_file, "--asset", "10.10.0.5", "--tag", "in-scope"])
    assert rc == 0
    assert "tagged 10.10.0.5" in capsys.readouterr().out

    # adding the same tag again is reported as no-change
    cli.main(["tag", "add", "--db", db_file, "--asset", "10.10.0.5", "--tag", "in-scope"])
    assert "no change" in capsys.readouterr().out

    rc = cli.main(["tag", "list", "--db", db_file])
    assert rc == 0
    out = capsys.readouterr().out
    assert "10.10.0.5" in out and "in-scope" in out

    rc = cli.main(["tag", "rm", "--db", db_file, "--asset", "10.10.0.5", "--tag", "in-scope"])
    assert rc == 0
    assert "removed 'in-scope'" in capsys.readouterr().out

    cli.main(["tag", "list", "--db", db_file])
    assert "no tags" in capsys.readouterr().out


def test_cli_tag_add_unknown_asset_errors(tmp_path, monkeypatch, capsys):
    db_file = _seed_one_asset_db(tmp_path, monkeypatch)
    capsys.readouterr()
    rc = cli.main(["tag", "add", "--db", db_file, "--asset", "10.10.9.9", "--tag", "x"])
    assert rc == 1
    assert "no asset matching" in capsys.readouterr().err


def test_cli_dump_tag_filter(tmp_path, monkeypatch, capsys):
    db_file = _seed_one_asset_db(tmp_path, monkeypatch)
    # add a second asset directly so we have something to filter out
    import sqlite3

    conn = sqlite3.connect(db_file)
    try:
        conn.execute("INSERT INTO assets (ip, state) VALUES ('10.10.0.6', 'up')")
        conn.commit()
    finally:
        conn.close()
    cli.main(["tag", "add", "--db", db_file, "--asset", "10.10.0.5", "--tag", "vip"])
    capsys.readouterr()

    rc = cli.main(["dump", "--db", db_file, "--tag", "vip"])
    assert rc == 0
    state = json.loads(capsys.readouterr().out)
    assert [a["ip"] for a in state["assets"]] == ["10.10.0.5"]
    assert state["assets"][0]["tags"] == ["vip"]


def test_cli_dump_kev_only_filter(tmp_path, monkeypatch, capsys):
    import sqlite3

    db_file = str(tmp_path / "engagement-test.db")
    cli.main(["init", "--db", db_file])
    conn = sqlite3.connect(db_file)
    try:
        conn.execute("INSERT INTO assets (id, ip, state) VALUES (1, '10.10.0.5', 'up')")
        conn.execute(
            "INSERT INTO services (id, asset_id, port, protocol, name, product, "
            "version) VALUES (1, 1, 80, 'tcp', 'http', 'nginx', '1.18.0')"
        )
        conn.execute(
            "INSERT INTO findings (service_id, cve_id, summary, severity, epss_score, "
            "kev) VALUES (1, 'CVE-HOT', 'x', '9.8', 0.9, 1)"
        )
        conn.execute(
            "INSERT INTO findings (service_id, cve_id, summary, severity, epss_score, "
            "kev) VALUES (1, 'CVE-COLD', 'y', '3.0', 0.01, 0)"
        )
        conn.commit()
    finally:
        conn.close()
    capsys.readouterr()

    rc = cli.main(["dump", "--db", db_file, "--kev-only"])
    assert rc == 0
    state = json.loads(capsys.readouterr().out)
    cves = [
        f["cve_id"]
        for a in state["assets"]
        for s in a["services"]
        for f in s["findings"]
    ]
    assert cves == ["CVE-HOT"]


def test_cli_dump_sarif_format(tmp_path, monkeypatch, capsys):
    import sqlite3

    db_file = str(tmp_path / "engagement-test.db")
    cli.main(["init", "--db", db_file])
    conn = sqlite3.connect(db_file)
    try:
        conn.execute("INSERT INTO assets (id, ip, state) VALUES (1, '10.10.0.5', 'up')")
        conn.execute(
            "INSERT INTO services (id, asset_id, port, protocol, name, product, "
            "version) VALUES (1, 1, 80, 'tcp', 'http', 'nginx', '1.18.0')"
        )
        conn.execute(
            "INSERT INTO findings (service_id, cve_id, summary, severity, epss_score, "
            "kev) VALUES (1, 'CVE-2021-23017', 'off-by-one', '7.7', 0.5, 1)"
        )
        conn.commit()
    finally:
        conn.close()
    capsys.readouterr()

    rc = cli.main(["dump", "--db", db_file, "--format", "sarif"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "ossuary"
    assert run["results"][0]["ruleId"] == "CVE-2021-23017"
    # KEV finding is escalated to error level.
    assert run["results"][0]["level"] == "error"


def test_cli_dump_jira_format(tmp_path, monkeypatch, capsys):
    import csv
    import io
    import sqlite3

    db_file = str(tmp_path / "engagement-test.db")
    cli.main(["init", "--db", db_file])
    conn = sqlite3.connect(db_file)
    try:
        conn.execute("INSERT INTO assets (id, ip, state) VALUES (1, '10.10.0.5', 'up')")
        conn.execute(
            "INSERT INTO services (id, asset_id, port, protocol, name, product, "
            "version) VALUES (1, 1, 80, 'tcp', 'http', 'nginx', '1.18.0')"
        )
        conn.execute(
            "INSERT INTO findings (service_id, cve_id, summary, severity, epss_score, "
            "kev) VALUES (1, 'CVE-2021-23017', 'off-by-one', '7.7', 0.5, 1)"
        )
        conn.commit()
    finally:
        conn.close()
    capsys.readouterr()

    rc = cli.main(["dump", "--db", db_file, "--format", "jira"])
    assert rc == 0
    rows = list(csv.reader(io.StringIO(capsys.readouterr().out)))
    assert rows[0][:4] == ["Summary", "Description", "Priority", "Labels"]
    row = dict(zip(rows[0], rows[1]))
    assert row["CVE"] == "CVE-2021-23017"
    # KEV finding maps to the top priority and carries the kev label.
    assert row["Priority"] == "Highest"
    assert "kev" in row["Labels"].split(";")


def test_cli_dump_cyclonedx_format(tmp_path, monkeypatch, capsys):
    import json
    import sqlite3

    db_file = str(tmp_path / "engagement-test.db")
    cli.main(["init", "--db", db_file])
    conn = sqlite3.connect(db_file)
    try:
        conn.execute("INSERT INTO assets (id, ip, state) VALUES (1, '10.10.0.5', 'up')")
        conn.execute(
            "INSERT INTO services (id, asset_id, port, protocol, name, product, "
            "version) VALUES (1, 1, 80, 'tcp', 'http', 'nginx', '1.18.0')"
        )
        conn.execute(
            "INSERT INTO findings (service_id, cve_id, summary, severity, epss_score, "
            "kev) VALUES (1, 'CVE-2021-23017', 'off-by-one', '7.7', 0.5, 1)"
        )
        conn.commit()
    finally:
        conn.close()
    capsys.readouterr()

    rc = cli.main(["dump", "--db", db_file, "--format", "cyclonedx"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["components"][0]["bom-ref"] == "10.10.0.5:tcp/80"
    vuln = doc["vulnerabilities"][0]
    assert vuln["id"] == "CVE-2021-23017"
    # The vulnerability links back to the component it was matched against.
    assert vuln["affects"][0]["ref"] == "10.10.0.5:tcp/80"


def test_cli_dump_spdx_format(tmp_path, monkeypatch, capsys):
    import json
    import sqlite3

    db_file = str(tmp_path / "engagement-test.db")
    cli.main(["init", "--db", db_file])
    conn = sqlite3.connect(db_file)
    try:
        conn.execute("INSERT INTO assets (id, ip, state) VALUES (1, '10.10.0.5', 'up')")
        conn.execute(
            "INSERT INTO services (id, asset_id, port, protocol, name, product, "
            "version, cpe) VALUES (1, 1, 80, 'tcp', 'http', 'nginx', '1.18.0', "
            "'cpe:/a:nginx')"
        )
        conn.execute(
            "INSERT INTO findings (service_id, cve_id, summary, severity, epss_score, "
            "kev) VALUES (1, 'CVE-2021-23017', 'off-by-one', '7.7', 0.5, 1)"
        )
        conn.commit()
    finally:
        conn.close()
    capsys.readouterr()

    rc = cli.main(["dump", "--db", db_file, "--format", "spdx"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["spdxVersion"] == "SPDX-2.3"
    pkg = doc["packages"][0]
    assert pkg["SPDXID"] == "SPDXRef-10.10.0.5-tcp-80"
    assert pkg["name"] == "nginx"
    # The matched CVE rides as a SECURITY external reference on its package.
    cve_refs = [
        r["referenceLocator"]
        for r in pkg["externalRefs"]
        if r["referenceType"] == "cve"
    ]
    assert cve_refs == ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"]
    # The document DESCRIBES the package.
    assert doc["relationships"][0]["relatedSpdxElement"] == pkg["SPDXID"]


def test_cli_dump_trivy_table_format(tmp_path, monkeypatch, capsys):
    """The CLI exposes `--format trivy-table` and emits Trivy's familiar shape."""
    import sqlite3

    db_file = str(tmp_path / "engagement-test.db")
    cli.main(["init", "--db", db_file])
    conn = sqlite3.connect(db_file)
    try:
        conn.execute(
            "INSERT INTO assets (id, ip, hostname, state) "
            "VALUES (1, '10.10.0.5', 'host-a', 'up')"
        )
        conn.execute(
            "INSERT INTO services (id, asset_id, port, protocol, name, product, "
            "version, cpe) VALUES (1, 1, 80, 'tcp', 'http', 'nginx', '1.18.0', "
            "'cpe:/a:nginx')"
        )
        conn.execute(
            "INSERT INTO findings (service_id, cve_id, summary, severity, epss_score, "
            "kev) VALUES (1, 'CVE-2021-23017', 'off-by-one', '7.7', 0.5, 1)"
        )
        conn.commit()
    finally:
        conn.close()
    capsys.readouterr()

    rc = cli.main(["dump", "--db", db_file, "--format", "trivy-table"])
    assert rc == 0
    out = capsys.readouterr().out
    # Target header reads as host (ip):port/proto (product version).
    assert "host-a (10.10.0.5):80/tcp (nginx 1.18.0)" in out
    # Trivy's per-target summary line lands in the output.
    assert "Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)" in out
    # The KEV signal rides as an inline marker in the Title cell.
    assert "[KEV]" in out
    # Trivy's box-drawing glyphs render the table.
    assert "│" in out and "─" in out


def test_cli_dump_sort_by_priority(tmp_path, monkeypatch, capsys):
    import sqlite3

    db_file = str(tmp_path / "engagement-test.db")
    cli.main(["init", "--db", db_file])
    conn = sqlite3.connect(db_file)
    try:
        conn.execute("INSERT INTO assets (id, ip, state) VALUES (1, '10.10.0.5', 'up')")
        conn.execute(
            "INSERT INTO services (id, asset_id, port, protocol, name, product, "
            "version) VALUES (1, 1, 80, 'tcp', 'http', 'nginx', '1.18.0')"
        )
        # Insert in non-priority order; the flag must reorder them.
        conn.execute(
            "INSERT INTO findings (service_id, cve_id, summary, severity, epss_score, "
            "kev) VALUES (1, 'CVE-COLD', 'y', '3.0', 0.01, 0)"
        )
        conn.execute(
            "INSERT INTO findings (service_id, cve_id, summary, severity, epss_score, "
            "kev) VALUES (1, 'CVE-HOT', 'x', '9.8', 0.9, 1)"
        )
        conn.commit()
    finally:
        conn.close()
    capsys.readouterr()

    rc = cli.main(["dump", "--db", db_file, "--sort-by-priority"])
    assert rc == 0
    state = json.loads(capsys.readouterr().out)
    cves = [
        f["cve_id"]
        for a in state["assets"]
        for s in a["services"]
        for f in s["findings"]
    ]
    assert cves == ["CVE-HOT", "CVE-COLD"]


def test_cli_dump_since_until_recency_window(tmp_path, monkeypatch, capsys):
    import sqlite3

    db_file = str(tmp_path / "engagement-test.db")
    cli.main(["init", "--db", db_file])
    conn = sqlite3.connect(db_file)
    try:
        conn.execute("INSERT INTO assets (id, ip, state) VALUES (1, '10.10.0.5', 'up')")
        conn.execute(
            "INSERT INTO services (id, asset_id, port, protocol, name, product, "
            "version) VALUES (1, 1, 80, 'tcp', 'http', 'nginx', '1.18.0')"
        )
        conn.execute(
            "INSERT INTO findings (service_id, cve_id, summary, severity, matched_at) "
            "VALUES (1, 'CVE-OLD', 'x', '5.0', '2026-01-10 09:00:00')"
        )
        conn.execute(
            "INSERT INTO findings (service_id, cve_id, summary, severity, matched_at) "
            "VALUES (1, 'CVE-NEW', 'y', '5.0', '2026-05-29 14:30:00')"
        )
        conn.commit()
    finally:
        conn.close()
    capsys.readouterr()

    rc = cli.main(["dump", "--db", db_file, "--since", "2026-05-01"])
    assert rc == 0
    state = json.loads(capsys.readouterr().out)
    cves = [
        f["cve_id"]
        for a in state["assets"]
        for s in a["services"]
        for f in s["findings"]
    ]
    assert cves == ["CVE-NEW"]


def test_cli_cruise_reports_tag_changes(tmp_path, monkeypatch, capsys):
    db_file = str(tmp_path / "engagement-test.db")
    monkeypatch.setattr(
        discover,
        "scan_hosts",
        lambda targets, arguments="-sn": host_discovery_result(up_ips=["10.10.0.5"]),
    )
    monkeypatch.setattr(
        fingerprint,
        "scan_services",
        lambda ip, arguments="-sV": service_scan_result(
            ip, [{"port": 22, "name": "ssh", "product": "OpenSSH", "version": "8.9p1"}]
        ),
    )
    cli.main(["init", "--db", db_file])
    cli.main(["discover", "--db", db_file, "--targets", str(TARGETS_FILE)])

    # first cruise establishes a baseline (no tags yet)
    cli.main(["cruise", "--db", db_file])
    # add a tag, then cruise again — the tag should appear as a change
    cli.main(["tag", "add", "--db", db_file, "--asset", "10.10.0.5", "--tag", "vip"])
    capsys.readouterr()

    rc = cli.main(["cruise", "--db", db_file])
    assert rc == 0
    out = capsys.readouterr().out
    assert "tag change" in out
    diff = json.loads(out[out.index("{") :])
    assert diff["tag_changes"][0]["asset"] == "10.10.0.5"
    assert diff["tag_changes"][0]["added"] == ["vip"]


def test_cli_cruise_runs_and_exits_zero(tmp_path, monkeypatch, capsys):
    db_file = str(tmp_path / "engagement-test.db")
    monkeypatch.setattr(
        discover,
        "scan_hosts",
        lambda targets, arguments="-sn": host_discovery_result(up_ips=["10.10.0.5"]),
    )
    monkeypatch.setattr(
        fingerprint,
        "scan_services",
        lambda ip, arguments="-sV": service_scan_result(
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


def test_cli_stats_text_summary(tmp_path, capsys):
    """`stats` prints a headline summary against a seeded DB (POST_V01 Rank 10)."""
    from ossuary import db

    db_file = str(tmp_path / "engagement-test.db")
    conn = db.init_db(db_file)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        sid = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
        db.upsert_finding(conn, sid, "CVE-HOT", "exploited", "9.8",
                          epss_score=0.94, kev=1)
        conn.commit()
    finally:
        conn.close()

    rc = cli.main(["stats", "--db", db_file])
    assert rc == 0
    out = capsys.readouterr().out
    assert "assets:   1" in out
    assert "KEV (actively exploited): 1" in out
    assert "CVE-HOT" in out


def test_cli_stats_json_format(tmp_path, capsys):
    db_file = str(tmp_path / "engagement-test.db")
    cli.main(["init", "--db", db_file])
    capsys.readouterr()
    rc = cli.main(["stats", "--db", db_file, "--format", "json"])
    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["assets"] == 0
    assert summary["top_findings"] == []


def test_cli_stats_tag_scopes_summary(tmp_path, capsys):
    """`stats --tag` scopes the roll-up to tagged assets, like `dump --tag`."""
    from ossuary import db, tags

    db_file = str(tmp_path / "engagement-test.db")
    conn = db.init_db(db_file)
    try:
        a = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        b = db.upsert_asset(conn, "10.10.0.6", "host-b", "up")
        sa = db.upsert_service(conn, a, 80, "tcp", "http", "nginx", "1.18.0", None)
        sb = db.upsert_service(conn, b, 443, "tcp", "https", "nginx", "1.20.0", None)
        db.upsert_finding(conn, sa, "CVE-A", "exploited", "9.8", epss_score=0.9, kev=1)
        db.upsert_finding(conn, sb, "CVE-B", "noise", "3.0", epss_score=0.02, kev=0)
        conn.commit()
    finally:
        conn.close()
    tags.add_tag(db_file, "10.10.0.5", "in-scope")
    capsys.readouterr()

    rc = cli.main(["stats", "--db", db_file, "--tag", "in-scope"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "engagement summary (tag: in-scope)" in out
    assert "assets:   1" in out
    assert "CVE-A" in out
    assert "CVE-B" not in out


def test_cli_stats_actionability_filters_scope_summary(tmp_path, capsys):
    """`stats --kev-only` / `--min-epss` / `--min-severity` mirror `dump`'s filters."""
    from ossuary import db

    db_file = str(tmp_path / "engagement-test.db")
    conn = db.init_db(db_file)
    try:
        aid = db.upsert_asset(conn, "10.10.0.5", "host-a", "up")
        s80 = db.upsert_service(conn, aid, 80, "tcp", "http", "nginx", "1.18.0", None)
        s22 = db.upsert_service(conn, aid, 22, "tcp", "ssh", "OpenSSH", "8.2", None)
        db.upsert_finding(conn, s80, "CVE-HOT", "exploited", "9.8",
                          epss_score=0.94, kev=1)
        db.upsert_finding(conn, s80, "CVE-COLD", "theoretical", "3.1",
                          epss_score=0.02, kev=0)
        db.upsert_finding(conn, s22, "CVE-MID", "needs auth", "6.5",
                          epss_score=None, kev=0)
        conn.commit()
    finally:
        conn.close()
    capsys.readouterr()

    rc = cli.main(["stats", "--db", db_file, "--kev-only", "--format", "json"])
    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    # only the KEV finding (and its service / asset) survives the filter
    assert summary["findings"] == 1
    assert summary["services"] == 1
    assert summary["kev"] == 1
    assert [f["cve_id"] for f in summary["top_findings"]] == ["CVE-HOT"]


def test_cli_stats_filter_header_records_scope(tmp_path, capsys):
    db_file = str(tmp_path / "engagement-test.db")
    cli.main(["init", "--db", db_file])
    capsys.readouterr()
    rc = cli.main(["stats", "--db", db_file, "--min-severity", "7.0"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "severity>=7" in out.splitlines()[0]
