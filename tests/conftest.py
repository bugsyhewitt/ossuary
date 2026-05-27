"""Shared pytest fixtures and nmap / OSV.dev mock builders.

No test in this suite touches the network. The nmap shell-out (in
discover.scan_hosts / fingerprint.scan_services), the OSV.dev HTTP call (in
cves.query_osv), and the enrichment HTTP calls (enrich.query_epss for FIRST
EPSS and enrich.fetch_kev_catalog for the CISA KEV catalog) are all
monkeypatched to return canned, python-nmap-shaped, OSV-shaped, and
EPSS/KEV-shaped structures.

The nmap-shaped builders (`host_discovery_result`, `service_scan_result`) are
re-exported from the shared `nmap-wrapper` library so the whole necromancer
suite mocks against one canonical python-nmap dict shape rather than per-repo
copies.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# Re-exported from the shared library so every consumer mocks the same shapes.
from nmap_wrapper.testing import (  # noqa: F401  (re-exported for tests)
    host_discovery_result,
    service_scan_result,
)

FIXTURES = Path(__file__).parent / "fixtures"
TARGETS_FILE = FIXTURES / "targets.txt"


@pytest.fixture
def db_path(tmp_path) -> Path:
    """A path for a fresh engagement DB inside an isolated tmp dir."""
    return tmp_path / "engagement-test.db"


# --------------------------------------------------------------------------
# OSV.dev-shaped builder
# --------------------------------------------------------------------------

def osv_response(vulns: list[dict] | None = None) -> dict:
    """Build an OSV.dev `/v1/query` response.

    `vulns` is a list of {id, aliases, summary, severity} partials. Empty/None
    yields the OSV "no vulns" response shape ({}).
    """
    if not vulns:
        return {}
    return {"vulns": vulns}


# --------------------------------------------------------------------------
# NVD CVE API v2-shaped builder
# --------------------------------------------------------------------------

def nvd_response(cves: list[dict] | None = None) -> dict:
    """Build an NVD CVE API v2 response.

    `cves` is a list of {id, summary, base_score} partials. Each is wrapped in
    the v2 schema's `vulnerabilities[].cve` envelope with an English description
    and (when base_score is given) a CVSS v3.1 metric. Empty/None yields the
    NVD "no results" shape ({"vulnerabilities": []}).
    """
    vulnerabilities = []
    for entry in cves or []:
        cve: dict = {"id": entry["id"]}
        if entry.get("summary") is not None:
            cve["descriptions"] = [{"lang": "en", "value": entry["summary"]}]
        if entry.get("base_score") is not None:
            cve["metrics"] = {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": entry["base_score"]}}
                ]
            }
        vulnerabilities.append({"cve": cve})
    return {"vulnerabilities": vulnerabilities}
