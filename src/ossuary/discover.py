"""Host discovery for ossuary.

Reads CIDR ranges / IP lists from a targets file, shells out to nmap for host
discovery, and persists the live hosts into the `assets` table.

The seam we mock in tests is `scan_hosts` — it is the only function that
touches the network. Everything below it is pure logic over its return value.
"""

from __future__ import annotations

from pathlib import Path

import nmap

from . import db


def read_targets(targets_path: str | Path) -> list[str]:
    """Parse a targets file into a list of target strings.

    One target per line. Blank lines and `#` comments are ignored. A target
    may be a single IP, a hostname, or a CIDR range — nmap handles each.
    """
    targets: list[str] = []
    for raw in Path(targets_path).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    return targets


def scan_hosts(targets: list[str]) -> dict:
    """Run an nmap host-discovery (ping) scan over the targets.

    Returns the raw python-nmap scan result dict. This is the network seam —
    tests monkeypatch this function so no live scan is performed.
    """
    scanner = nmap.PortScanner()
    # -sn: ping scan, no port scan. Discovery only; fingerprinting is separate.
    scanner.scan(hosts=" ".join(targets), arguments="-sn")
    return scanner._scan_result


def parse_hosts(scan_result: dict) -> list[dict]:
    """Extract up hosts from a python-nmap scan result dict.

    Returns a list of {"ip", "hostname", "state"} dicts for hosts that nmap
    reported as `up`.
    """
    hosts: list[dict] = []
    scan = scan_result.get("scan", {})
    for ip, host_data in scan.items():
        status = host_data.get("status", {})
        state = status.get("state", "unknown")
        if state != "up":
            continue
        hostnames = host_data.get("hostnames", []) or []
        hostname = None
        if hostnames:
            hostname = hostnames[0].get("name") or None
        hosts.append({"ip": ip, "hostname": hostname, "state": state})
    return hosts


def discover(db_path: str | Path, targets_path: str | Path) -> int:
    """Discover hosts and populate the `assets` table.

    Returns the number of live assets persisted.
    """
    targets = read_targets(targets_path)
    if not targets:
        return 0
    scan_result = scan_hosts(targets)
    hosts = parse_hosts(scan_result)

    conn = db.require_initialised(db_path)
    try:
        for host in hosts:
            db.upsert_asset(conn, host["ip"], host["hostname"], host["state"])
        conn.commit()
    finally:
        conn.close()
    return len(hosts)
