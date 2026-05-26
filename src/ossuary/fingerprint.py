"""Service fingerprinting for ossuary.

For each known asset, shells out to nmap service/version detection (-sV) via the
shared ``nmap-wrapper`` library and persists the discovered services (name +
product + version + cpe) into the `services` table.

`scan_services` is the network seam mocked in tests.
"""

from __future__ import annotations

from pathlib import Path

from nmap_wrapper import parse_services as _wrapper_parse_services
from nmap_wrapper import raw_scan

from . import db


def scan_services(ip: str) -> dict:
    """Run an nmap service/version-detection scan against a single host.

    Returns the raw python-nmap scan result dict. Network seam — mocked in
    tests so no live scan runs. The shell-out is delegated to the shared
    ``nmap-wrapper`` library.
    """
    # -sV: probe open ports to determine service/version info.
    return raw_scan(ip, arguments="-sV")


def parse_services(ip: str, scan_result: dict) -> list[dict]:
    """Extract open services for one host from a python-nmap scan result.

    Returns a list of service dicts with keys: port, protocol, name, product,
    version, cpe. Only ports in `open` state are returned. Parsing is delegated
    to ``nmap-wrapper``; its typed services are filtered to open ports and
    mapped to ossuary's persistence shape.
    """
    return [
        {
            "port": svc.port,
            "protocol": svc.protocol,
            "name": svc.name,
            "product": svc.product,
            "version": svc.version,
            "cpe": svc.cpe,
        }
        for svc in _wrapper_parse_services(ip, scan_result)
        if svc.is_open
    ]


def fingerprint(db_path: str | Path) -> int:
    """Fingerprint every known asset, populating the `services` table.

    Returns the number of service rows written/updated across all assets.
    """
    conn = db.require_initialised(db_path)
    try:
        assets = conn.execute("SELECT id, ip FROM assets WHERE state = 'up'").fetchall()
        total = 0
        for asset in assets:
            scan_result = scan_services(asset["ip"])
            # [Worker decision: fingerprint reflects the *current* live state of
            # an asset, not an append-only union. We delete this asset's prior
            # services before re-inserting so a port that closed between scans
            # actually disappears from the services table. This is what makes
            # cruise's "removed" diff work — without it, closed ports would
            # linger forever. Findings cascade-delete with their services; they
            # are re-derived on the next match-cves run.]
            conn.execute("DELETE FROM services WHERE asset_id = ?", (int(asset["id"]),))
            for svc in parse_services(asset["ip"], scan_result):
                db.upsert_service(
                    conn,
                    asset_id=int(asset["id"]),
                    port=svc["port"],
                    protocol=svc["protocol"],
                    name=svc["name"],
                    product=svc["product"],
                    version=svc["version"],
                    cpe=svc["cpe"],
                )
                total += 1
        conn.commit()
    finally:
        conn.close()
    return total
