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

Actionability filters (``min_epss`` / ``min_severity`` / ``kev_only``) trim the
export to the findings that actually matter for a report. NIST's enrichment
retreat left raw CVSS blank on most fresh CVEs, so the live prioritisation
signal lives in EPSS (exploit probability) and CISA KEV (confirmed exploited).
These filters let a hunter close an engagement with "only the findings worth
writing up." A finding survives the filters when it clears *every* threshold
given; when no filters are given, the export is unchanged (full inventory).

Priority ordering (``sort_by_priority``) reorders each service's findings to
match the triage order ``match-cves`` already prints to the console — KEV-first,
then descending EPSS, then descending numeric severity, then CVE id — so the
most-exploited findings lead every report. It is off by default, leaving the
historical alphabetical-by-CVE-id ordering byte-for-byte unchanged.
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


def _parse_severity(value) -> float | None:
    """Best-effort parse of a finding's free-text severity into a float.

    Severity is stored as text (it may be a CVSS base score like ``7.7`` or a
    blank for un-enriched CVEs). A value that doesn't parse as a number — or a
    blank — is treated as "unknown" and returns ``None``.
    """
    if value is None:
        return None
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _finding_is_actionable(
    finding: dict,
    min_epss: float | None,
    min_severity: float | None,
    kev_only: bool,
) -> bool:
    """Return True when a finding clears every supplied actionability threshold.

    With no thresholds the finding always passes. ``kev_only`` requires KEV=1.
    ``min_epss`` requires a present EPSS score >= the floor (a finding with no
    EPSS score is excluded once an EPSS floor is set). ``min_severity`` requires
    a parseable severity >= the floor (un-parseable / blank severities are
    excluded once a severity floor is set).
    """
    if kev_only and not finding.get("kev"):
        return False
    if min_epss is not None:
        epss = finding.get("epss_score")
        if epss is None or epss < min_epss:
            return False
    if min_severity is not None:
        sev = _parse_severity(finding.get("severity"))
        if sev is None or sev < min_severity:
            return False
    return True


def _priority_key(finding: dict) -> tuple:
    """Sort key ranking a finding by exploitation signal, highest-priority first.

    Mirrors the triage order ``match-cves`` prints to the console:
    KEV-first, then descending EPSS, then descending numeric severity, then
    CVE id (ascending) as a stable final tiebreaker. Missing EPSS / severity
    sink to the bottom of their tier. Built for use with ``sorted`` (ascending),
    so the signal fields are negated and absent values map to the lowest rank.
    """
    kev = 1 if finding.get("kev") else 0
    epss = finding.get("epss_score")
    epss = epss if epss is not None else -1.0
    sev = _parse_severity(finding.get("severity"))
    sev = sev if sev is not None else -1.0
    cve_id = finding.get("cve_id") or ""
    # Negate the three signal fields so larger = earlier under ascending sort;
    # cve_id stays ascending as the deterministic final tiebreaker.
    return (-kev, -epss, -sev, cve_id)


def build_state(
    conn: sqlite3.Connection,
    tag: str | None = None,
    *,
    min_epss: float | None = None,
    min_severity: float | None = None,
    kev_only: bool = False,
    sort_by_priority: bool = False,
) -> dict:
    """Assemble the full engagement state as a nested dict.

    When `tag` is given, only assets carrying that tag label are included — the
    workflow filter for "show me just my in-scope / VIP / priority hosts."

    `min_epss`, `min_severity`, and `kev_only` are actionability filters applied
    at the finding level. When any is set, findings that don't clear the
    threshold(s) are dropped, and services / assets left with no surviving
    findings are pruned from the output — so the export collapses to just the
    findings worth reporting. With none set, the full inventory is returned
    (services with no findings still appear), preserving the prior behaviour.

    When `sort_by_priority` is set, each service's findings are reordered
    KEV-first, then by descending EPSS, descending numeric severity, and finally
    CVE id — the same triage order `match-cves` prints — so the highest-signal
    findings lead. When unset, findings keep their alphabetical-by-CVE-id order.
    """
    filtering = min_epss is not None or min_severity is not None or kev_only
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
            findings_out = [dict(f) for f in findings]
            if filtering:
                findings_out = [
                    f
                    for f in findings_out
                    if _finding_is_actionable(f, min_epss, min_severity, kev_only)
                ]
                # When filtering for actionable findings, a service with none
                # left carries no signal — drop it so the report shows only hits.
                if not findings_out:
                    continue
            if sort_by_priority:
                findings_out.sort(key=_priority_key)
            services_out.append(
                {
                    "port": svc["port"],
                    "protocol": svc["protocol"],
                    "name": svc["name"],
                    "product": svc["product"],
                    "version": svc["version"],
                    "cpe": svc["cpe"],
                    "fingerprinted_at": svc["fingerprinted_at"],
                    "findings": findings_out,
                }
            )
        # Likewise prune assets with no surviving services when filtering.
        if filtering and not services_out:
            continue
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


def dump(
    db_path: str | Path,
    fmt: str = "json",
    tag: str | None = None,
    *,
    min_epss: float | None = None,
    min_severity: float | None = None,
    kev_only: bool = False,
    sort_by_priority: bool = False,
) -> str:
    """Return the engagement state as a serialised string in the given format.

    `fmt` is one of ``json``, ``csv``, or ``markdown``. `tag`, when set,
    restricts the export to assets carrying that tag label. `min_epss`,
    `min_severity`, and `kev_only` are actionability filters: each restricts the
    export to findings clearing that threshold, pruning services and assets left
    with no surviving findings. They compose with `tag` and with each other.
    `sort_by_priority`, when set, orders each service's findings KEV-first /
    descending-EPSS / descending-severity / CVE-id (the `match-cves` triage
    order) instead of the default alphabetical-by-CVE-id ordering.
    """
    if fmt not in SUPPORTED_FORMATS:
        supported = ", ".join(SUPPORTED_FORMATS)
        raise ValueError(
            f"unsupported dump format {fmt!r} (supported: {supported})"
        )
    conn = db.require_initialised(db_path)
    try:
        state = build_state(
            conn,
            tag=tag,
            min_epss=min_epss,
            min_severity=min_severity,
            kev_only=kev_only,
            sort_by_priority=sort_by_priority,
        )
    finally:
        conn.close()
    if fmt == "csv":
        return to_csv(state)
    if fmt == "markdown":
        return to_markdown(state)
    return json.dumps(state, indent=2, sort_keys=False)
