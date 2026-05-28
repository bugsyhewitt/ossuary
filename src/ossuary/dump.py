"""Engagement state export for ossuary.

Serialises the full engagement (assets + their services + each service's
findings) to one of three shapes:

  * ``json``     — the nested structure (assets → services → findings) suitable
                   for piping into other tools.
  * ``csv``      — a flat table, one finding per row (with a header row),
                   joining asset + service + finding context. Services with no
                   findings still emit a row so no inventory is lost.
  * ``markdown`` — the same flat table as a GitHub-Flavoured-Markdown pipe
                   table, ready to paste into a HackerOne / Bugcrowd report.

The flat formats cover exactly the same fields as the JSON output, flattened
across the asset/service/finding nesting.
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
from pathlib import Path

from . import db, tags

SUPPORTED_FORMATS = ("json", "csv", "markdown")

# Columns for the flat (CSV / Markdown) exports, in emission order. These join
# the asset-, service-, and finding-level fields the JSON dump exposes.
FLAT_COLUMNS = [
    "ip",
    "hostname",
    "asset_state",
    "discovered_at",
    "tags",
    "port",
    "protocol",
    "service_name",
    "product",
    "version",
    "cpe",
    "fingerprinted_at",
    "cve_id",
    "summary",
    "severity",
    "source",
    "epss_score",
    "kev",
    "matched_at",
]


def build_state(conn: sqlite3.Connection, tag: str | None = None) -> dict:
    """Assemble the full engagement state as a nested dict.

    When `tag` is given, only assets carrying that tag label are included — the
    workflow filter for "show me just my in-scope / VIP / priority hosts."
    """
    assets_out: list[dict] = []
    if tag is not None:
        assets = conn.execute(
            """
            SELECT a.id, a.ip, a.hostname, a.state, a.discovered_at
            FROM assets a
            JOIN tags t ON t.entity = 'asset' AND t.entity_id = a.id
            WHERE t.tag = ?
            ORDER BY a.ip
            """,
            (tag,),
        ).fetchall()
    else:
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
                "SELECT cve_id, summary, severity, source, epss_score, kev, "
                "matched_at FROM findings WHERE service_id = ? ORDER BY cve_id",
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
                "tags": tags.asset_tags(conn, asset["id"]),
                "services": services_out,
            }
        )
    return {"assets": assets_out}


def _flat_rows(state: dict) -> list[dict]:
    """Flatten the nested engagement state to one dict per finding.

    A service with no findings still yields one row (empty finding columns) so
    the export never silently drops inventory. Tags are joined with ``;`` into a
    single cell.
    """
    rows: list[dict] = []
    for asset in state["assets"]:
        asset_base = {
            "ip": asset["ip"],
            "hostname": asset["hostname"],
            "asset_state": asset["state"],
            "discovered_at": asset["discovered_at"],
            "tags": ";".join(asset.get("tags") or []),
        }
        for svc in asset["services"]:
            svc_base = {
                **asset_base,
                "port": svc["port"],
                "protocol": svc["protocol"],
                "service_name": svc["name"],
                "product": svc["product"],
                "version": svc["version"],
                "cpe": svc["cpe"],
                "fingerprinted_at": svc["fingerprinted_at"],
            }
            findings = svc["findings"]
            if not findings:
                rows.append({**svc_base})
                continue
            for f in findings:
                rows.append(
                    {
                        **svc_base,
                        "cve_id": f.get("cve_id"),
                        "summary": f.get("summary"),
                        "severity": f.get("severity"),
                        "source": f.get("source"),
                        "epss_score": f.get("epss_score"),
                        "kev": f.get("kev"),
                        "matched_at": f.get("matched_at"),
                    }
                )
    return rows


def _cell(value) -> str:
    """Render a value as a flat-export cell. ``None`` becomes the empty string."""
    return "" if value is None else str(value)


def to_csv(state: dict) -> str:
    """Serialise the engagement state as CSV with a header row."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(FLAT_COLUMNS)
    for row in _flat_rows(state):
        writer.writerow([_cell(row.get(col)) for col in FLAT_COLUMNS])
    return buf.getvalue()


def _md_escape(value) -> str:
    """Escape a cell for a Markdown pipe table (pipes and newlines)."""
    text = _cell(value)
    return text.replace("\\", "\\\\").replace("|", r"\|").replace("\n", "<br>")


def to_markdown(state: dict) -> str:
    """Serialise the engagement state as a GitHub-Flavoured-Markdown table."""
    lines = [
        "| " + " | ".join(FLAT_COLUMNS) + " |",
        "| " + " | ".join("---" for _ in FLAT_COLUMNS) + " |",
    ]
    for row in _flat_rows(state):
        lines.append(
            "| " + " | ".join(_md_escape(row.get(col)) for col in FLAT_COLUMNS) + " |"
        )
    return "\n".join(lines)


def dump(db_path: str | Path, fmt: str = "json", tag: str | None = None) -> str:
    """Return the engagement state as a serialised string in the given format.

    `fmt` is one of ``json``, ``csv``, or ``markdown``. `tag`, when set,
    restricts the export to assets carrying that tag label.
    """
    if fmt not in SUPPORTED_FORMATS:
        supported = ", ".join(SUPPORTED_FORMATS)
        raise ValueError(
            f"unsupported dump format {fmt!r} (supported: {supported})"
        )
    conn = db.require_initialised(db_path)
    try:
        state = build_state(conn, tag=tag)
    finally:
        conn.close()
    if fmt == "csv":
        return to_csv(state)
    if fmt == "markdown":
        return to_markdown(state)
    return json.dumps(state, indent=2, sort_keys=False)
