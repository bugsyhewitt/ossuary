"""Shared pytest fixtures and python-nmap / OSV.dev mock builders.

No test in this suite touches the network. The nmap shell-out (in
discover.scan_hosts / fingerprint.scan_services) and the OSV.dev HTTP call (in
cves.query_osv) are monkeypatched to return these canned, python-nmap-shaped
and OSV-shaped structures.
"""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
TARGETS_FILE = FIXTURES / "targets.txt"


@pytest.fixture
def db_path(tmp_path) -> Path:
    """A path for a fresh engagement DB inside an isolated tmp dir."""
    return tmp_path / "engagement-test.db"


# --------------------------------------------------------------------------
# python-nmap-shaped builders
# --------------------------------------------------------------------------

def host_discovery_result(up_ips: list[str], down_ips: list[str] | None = None) -> dict:
    """Build a python-nmap `_scan_result` for an `-sn` host-discovery scan."""
    down_ips = down_ips or []
    scan: dict = {}
    for ip in up_ips:
        scan[ip] = {
            "hostnames": [{"name": f"host-{ip.replace('.', '-')}", "type": "PTR"}],
            "addresses": {"ipv4": ip},
            "status": {"state": "up", "reason": "echo-reply"},
        }
    for ip in down_ips:
        scan[ip] = {
            "hostnames": [],
            "addresses": {"ipv4": ip},
            "status": {"state": "down", "reason": "no-response"},
        }
    return {"nmap": {"command_line": "nmap -sn ...", "scaninfo": {}}, "scan": scan}


def service_scan_result(ip: str, services: list[dict]) -> dict:
    """Build a python-nmap `_scan_result` for an `-sV` service scan of one host.

    `services` is a list of {port, name, product, version, [state]} dicts.
    """
    tcp: dict = {}
    for svc in services:
        tcp[svc["port"]] = {
            "state": svc.get("state", "open"),
            "name": svc.get("name", ""),
            "product": svc.get("product", ""),
            "version": svc.get("version", ""),
            "cpe": svc.get("cpe", ""),
        }
    return {
        "nmap": {"command_line": "nmap -sV ...", "scaninfo": {}},
        "scan": {ip: {"tcp": tcp, "status": {"state": "up"}}},
    }


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
