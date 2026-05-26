"""Engagement state export for ossuary.

Serialises the full engagement (assets + their services + each service's
findings) to a nested JSON structure suitable for piping into other tools.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from . import db


def build_state(conn: sqlite3.Connection) -> dict:
    """Assemble the full engagement state as a nested dict."""
    assets_out: list[dict] = []
    assets = conn.execute(
        "SELECT id, ip, hostname, state, discovered_at FROM assets ORDER BY ip"
    ).fetchall()
    for asset in assets:
        services_out: list[dict] = []
        services = conn.execute(
            "SELECT id, port, protocol, name, product, version, cpe, fingerprinted_at "
            "FROM services WHERE asset_id = ? ORDER BY port",
            (asset["id"],),
        ).fetchall()
        for svc in services:
            findings = conn.execute(
                "SELECT cve_id, summary, severity, source, matched_at "
                "FROM findings WHERE service_id = ? ORDER BY cve_id",
                (svc["id"],),
            ).fetchall()
            services_out.append(
                {
                    "port": svc["port"],
                    "protocol": svc["protocol"],
                    "name": svc["name"],
                    "product": svc["product"],
                    "version": svc["version"],
                    "cpe": svc["cpe"],
                    "fingerprinted_at": svc["fingerprinted_at"],
                    "findings": [dict(f) for f in findings],
                }
            )
        assets_out.append(
            {
                "ip": asset["ip"],
                "hostname": asset["hostname"],
                "state": asset["state"],
                "discovered_at": asset["discovered_at"],
                "services": services_out,
            }
        )
    return {"assets": assets_out}


def dump(db_path: str | Path, fmt: str = "json") -> str:
    """Return the engagement state as a serialised string in the given format."""
    if fmt != "json":
        raise ValueError(f"unsupported dump format {fmt!r} (v0.1 supports: json)")
    conn = db.require_initialised(db_path)
    try:
        state = build_state(conn)
    finally:
        conn.close()
    return json.dumps(state, indent=2, sort_keys=False)
