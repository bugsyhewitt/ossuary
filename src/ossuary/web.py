"""Web-layer inventory read surface for ossuary (`ossuary web`).

`ossuary probe` (Rank 3) is the *write* side of the HTTP/web layer: it sends an
HTTP HEAD/GET to each asset's open web port and persists the response — status
code, ``Server`` banner, page ``<title>``, redirect chain, and tech fingerprints
— into the ``web_probes`` table. But until now that data had no *read* surface.
A hunter who ran `probe` could see the live stdout summary once and never again;
the persisted web inventory was invisible to every other command (`dump` walks
assets → services → findings only, and never the web layer).

`ossuary web` closes that gap. It is to `probe` what `stats` / `stale` are to
`match-cves`: the read companion that surfaces the data already in the DB. It
lists every recorded web probe, joined to its owning asset, with the response
metadata a hunter triages a web surface by — "which hosts answer HTTP, what are
they running, where do they redirect, what's the page title."

Filters scope the listing without re-probing:

    --host HOST   only probes on a single asset (matched on IP or hostname)
    --tech TECH   only probes whose tech_fingerprints include TECH (e.g.
                  ``wordpress``, ``nginx``); case-insensitive substring match

Output is a human-readable text report (one block per probe, grouped by host)
or a JSON array carrying the same fields. The ``redirect_chain`` and
``tech_fingerprints`` columns are stored as JSON text by `probe`; this module
decodes them back into lists so both formats expose structured values rather than
raw JSON strings. No network calls, no new schema, no new dependencies.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from . import db

SUPPORTED_FORMATS = ("text", "json")


def _decode_json_list(value) -> list:
    """Decode a JSON-text column into a list, tolerating blanks / bad data.

    `probe` stores ``redirect_chain`` and ``tech_fingerprints`` via
    ``json.dumps(list)``. A NULL / blank / non-list / unparseable value degrades
    to an empty list so the read surface never raises on a malformed row.
    """
    if not value:
        return []
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError):
        return []
    return decoded if isinstance(decoded, list) else []


def build_web(
    conn: sqlite3.Connection,
    *,
    host: str | None = None,
    tech: str | None = None,
) -> dict:
    """Assemble the recorded web-probe inventory as a plain dict.

    Joins every ``web_probes`` row to its owning asset and returns them ordered
    by IP then port then protocol — a stable per-host walk. ``redirect_chain``
    and ``tech_fingerprints`` are decoded from their stored JSON text into lists.

    `host` restricts the listing to a single asset (matched on either IP or
    hostname). `tech` restricts it to probes whose decoded ``tech_fingerprints``
    include a case-insensitive substring match of TECH (so ``--tech wp`` matches
    ``wordpress``); the match is applied after decoding, in Python, so it works
    uniformly regardless of how the list was serialised.

    The returned dict carries a `count` and a `probes` list; each probe entry
    carries the locating host context plus the response metadata.
    """
    sql = (
        "SELECT a.ip AS ip, a.hostname AS hostname, "
        "w.port AS port, w.protocol AS protocol, w.status_code AS status_code, "
        "w.server AS server, w.title AS title, w.redirect_chain AS redirect_chain, "
        "w.tech_fingerprints AS tech_fingerprints, w.probed_at AS probed_at "
        "FROM web_probes w JOIN assets a ON a.id = w.asset_id"
    )
    params: list = []
    if host is not None:
        sql += " WHERE (a.ip = ? OR a.hostname = ?)"
        params += [host, host]
    sql += " ORDER BY a.ip, w.port, w.protocol"

    rows = conn.execute(sql, params).fetchall()

    tech_needle = tech.lower() if tech else None
    probes: list[dict] = []
    for row in rows:
        techs = _decode_json_list(row["tech_fingerprints"])
        if tech_needle is not None:
            if not any(tech_needle in str(t).lower() for t in techs):
                continue
        probes.append(
            {
                "ip": row["ip"],
                "hostname": row["hostname"],
                "port": row["port"],
                "protocol": row["protocol"],
                "status_code": row["status_code"],
                "server": row["server"],
                "title": row["title"],
                "redirect_chain": _decode_json_list(row["redirect_chain"]),
                "tech_fingerprints": techs,
                "probed_at": row["probed_at"],
            }
        )

    return {"count": len(probes), "probes": probes}


def _scope_suffix(*, host: str | None, tech: str | None) -> str:
    """Build the ``(...)`` scope suffix recording the active host / tech filter."""
    parts: list[str] = []
    if host is not None:
        parts.append(f"host: {host}")
    if tech is not None:
        parts.append(f"tech: {tech}")
    return f" ({', '.join(parts)})" if parts else ""


def to_text(report: dict, *, host: str | None = None, tech: str | None = None) -> str:
    """Render the web-probe inventory as a human-readable text block."""
    suffix = _scope_suffix(host=host, tech=tech)
    lines = [f"web inventory{suffix}", f"  count: {report['count']}"]
    if not report["probes"]:
        lines.append("  none — run `ossuary probe` to populate the web layer")
        return "\n".join(lines)
    for p in report["probes"]:
        loc = f"{p['protocol']}://{p['ip']}:{p['port']}"
        status = str(p["status_code"]) if p["status_code"] is not None else "err"
        lines.append(f"  {loc}  [{status}]")
        if p["hostname"]:
            lines.append(f"    hostname: {p['hostname']}")
        if p["server"]:
            lines.append(f"    server: {p['server']}")
        if p["title"]:
            lines.append(f"    title: {p['title']}")
        if p["tech_fingerprints"]:
            lines.append(f"    tech: {', '.join(p['tech_fingerprints'])}")
        if p["redirect_chain"]:
            lines.append(f"    redirects: {' -> '.join(p['redirect_chain'])}")
    return "\n".join(lines)


def web(
    db_path: str | Path,
    fmt: str = "text",
    *,
    host: str | None = None,
    tech: str | None = None,
) -> str:
    """Return the recorded web-probe inventory as a serialised string.

    `fmt` is ``text`` (human-readable, grouped per host) or ``json`` (the same
    rows as a structured array). `host` restricts the listing to a single asset
    (IP or hostname); `tech` restricts it to probes whose tech fingerprints
    include a case-insensitive substring match of TECH.
    """
    if fmt not in SUPPORTED_FORMATS:
        supported = ", ".join(SUPPORTED_FORMATS)
        raise ValueError(f"unsupported web format {fmt!r} (supported: {supported})")
    conn = db.require_initialised(db_path)
    try:
        report = build_web(conn, host=host, tech=tech)
    finally:
        conn.close()
    if fmt == "json":
        return json.dumps(report, indent=2, sort_keys=False)
    return to_text(report, host=host, tech=tech)
