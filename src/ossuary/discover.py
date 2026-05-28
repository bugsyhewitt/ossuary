"""Host discovery for ossuary.

Reads CIDR ranges / IP lists from a targets file, shells out to nmap (via the
shared ``nmap-wrapper`` library) for host discovery, and persists the live
hosts into the `assets` table.

The seam we mock in tests is `scan_hosts` — it is the only function that
touches the network. It delegates the actual shell-out to ``nmap-wrapper``;
everything below it is pure logic over its return value.
"""

from __future__ import annotations

from pathlib import Path

from nmap_wrapper import parse_scan_result, raw_scan

from . import db
from .profiles import DEFAULT_PROFILE, get_profile


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


def scan_hosts(targets: list[str], arguments: str = "-sn") -> dict:
    """Run an nmap host-discovery (ping) scan over the targets.

    Returns the raw python-nmap scan result dict. This is the network seam —
    tests monkeypatch this function so no live scan is performed. The actual
    shell-out is delegated to the shared ``nmap-wrapper`` library.

    `arguments` is the nmap flag string. It defaults to ``-sn`` (ping scan, no
    port scan — discovery only) but a named scan profile can override it.
    """
    return raw_scan(" ".join(targets), arguments=arguments)


def parse_hosts(scan_result: dict) -> list[dict]:
    """Extract up hosts from a python-nmap scan result dict.

    Returns a list of {"ip", "hostname", "state"} dicts for hosts that nmap
    reported as `up`. Parsing is delegated to ``nmap-wrapper`` and the typed
    hosts are mapped to ossuary's persistence shape.
    """
    result = parse_scan_result(scan_result)
    return [
        {"ip": h.ip, "hostname": h.hostname, "state": h.state}
        for h in result.up_hosts()
    ]


def discover(
    db_path: str | Path,
    targets_path: str | Path,
    profile: str = DEFAULT_PROFILE,
) -> int:
    """Discover hosts and populate the `assets` table.

    `profile` selects a named scan profile (see ossuary.profiles) whose
    `discover` flags drive the nmap scan; the profile name is recorded on each
    asset row so a later rediscovery under a different profile can be flagged.

    Returns the number of live assets persisted.
    """
    prof = get_profile(profile)
    targets = read_targets(targets_path)
    if not targets:
        return 0
    scan_result = scan_hosts(targets, arguments=prof.discover)
    hosts = parse_hosts(scan_result)

    conn = db.require_initialised(db_path)
    try:
        for host in hosts:
            db.upsert_asset(
                conn,
                host["ip"],
                host["hostname"],
                host["state"],
                scan_profile=prof.name,
            )
        conn.commit()
    finally:
        conn.close()
    return len(hosts)
