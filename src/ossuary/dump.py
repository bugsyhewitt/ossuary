"""Engagement state export for ossuary.

Serialises the full engagement (assets + their services + each service's
findings) to one of four shapes:

  * ``json``     — the nested structure (assets → services → findings) suitable
                   for piping into other tools.
  * ``csv``      — a flat table, one finding per row (with a header row),
                   joining asset + service + finding context. Services with no
                   findings still emit a row so no inventory is lost.
  * ``markdown`` — the same flat table as a GitHub-Flavoured-Markdown pipe
                   table, ready to paste into a HackerOne / Bugcrowd report.
  * ``html``     — a single self-contained HTML document (inline CSS, no
                   external assets) grouping findings under each asset and
                   service, with KEV badges and severity-tier colour coding —
                   the shareable, human-readable deliverable that closes the
                   report-export lineage. It carries the same data the other
                   formats do and respects the same filters / priority order.

The flat (csv / markdown) formats cover exactly the same fields as the JSON
output, flattened across the asset/service/finding nesting.

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
import html
import io
import json
import sqlite3
from pathlib import Path

from . import db, tags

SUPPORTED_FORMATS = ("json", "csv", "markdown", "html")

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


# --------------------------------------------------------------------------
# HTML report export (POST_V01 Rank 11)
# --------------------------------------------------------------------------

# Inline stylesheet for the self-contained report. Kept deliberately small and
# dependency-free: no web fonts, no external CSS, no JavaScript — the document
# renders identically offline and is safe to hand to a client.
_HTML_STYLE = """
  body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         margin: 2rem; color: #1a1a1a; background: #fafafa; }
  h1 { margin-bottom: 0.25rem; }
  .meta { color: #666; font-size: 0.9rem; margin-bottom: 1.5rem; }
  .asset { background: #fff; border: 1px solid #ddd; border-radius: 6px;
           padding: 1rem 1.25rem; margin-bottom: 1.25rem; }
  .asset h2 { margin: 0 0 0.25rem; font-size: 1.15rem; }
  .asset .tags { color: #555; font-size: 0.85rem; }
  .service { margin: 0.75rem 0 0.25rem; font-weight: 600; }
  table { border-collapse: collapse; width: 100%; margin: 0.25rem 0 0.75rem; }
  th, td { border: 1px solid #e2e2e2; padding: 0.35rem 0.5rem;
           text-align: left; font-size: 0.88rem; vertical-align: top; }
  th { background: #f0f0f0; }
  .badge { display: inline-block; padding: 0.05rem 0.4rem; border-radius: 4px;
           font-size: 0.72rem; font-weight: 700; color: #fff; }
  .kev { background: #b30000; }
  .sev-critical { background: #ffd6d6; }
  .sev-high { background: #ffe6cc; }
  .sev-medium { background: #fff5cc; }
  .sev-low { background: #e6f0ff; }
  .sev-blank { background: #f2f2f2; color: #888; }
  .empty { color: #888; font-style: italic; }
"""


def _severity_tier_class(value) -> str:
    """Map a finding's severity to a CSS tier class (mirrors stats tiering)."""
    sev = _parse_severity(value)
    if sev is None:
        return "sev-blank"
    if sev >= 9.0:
        return "sev-critical"
    if sev >= 7.0:
        return "sev-high"
    if sev >= 4.0:
        return "sev-medium"
    return "sev-low"


def _h(value) -> str:
    """HTML-escape a value, rendering ``None`` as an empty string."""
    return html.escape(_cell(value))


def to_html(state: dict) -> str:
    """Serialise the engagement state as a single self-contained HTML document.

    Findings are grouped under each asset and service (matching the nested JSON
    shape rather than the flat CSV/Markdown one), so the report reads as a
    per-host walk-through. KEV findings carry a red ``KEV`` badge and every
    finding row is colour-coded by severity tier. The document inlines all CSS
    and references no external assets, so it renders offline and is safe to hand
    to a client. An empty engagement still yields a valid document with an
    explicit empty-state notice.
    """
    asset_count = len(state["assets"])
    finding_count = sum(
        len(svc["findings"]) for a in state["assets"] for svc in a["services"]
    )
    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>ossuary engagement report</title>",
        f"<style>{_HTML_STYLE}</style>",
        "</head>",
        "<body>",
        "<h1>ossuary engagement report</h1>",
        f'<p class="meta">{asset_count} asset(s), {finding_count} finding(s)</p>',
    ]

    if not state["assets"]:
        parts.append('<p class="empty">No assets in this engagement.</p>')
    for asset in state["assets"]:
        host = _h(asset["hostname"]) if asset["hostname"] else ""
        heading = _h(asset["ip"]) + (f" <small>({host})</small>" if host else "")
        parts.append('<section class="asset">')
        parts.append(f"<h2>{heading}</h2>")
        asset_tags = asset.get("tags") or []
        if asset_tags:
            tag_str = ", ".join(_h(t) for t in asset_tags)
            parts.append(f'<div class="tags">tags: {tag_str}</div>')
        if not asset["services"]:
            parts.append('<p class="empty">No services.</p>')
        for svc in asset["services"]:
            label = f"{_h(svc['port'])}/{_h(svc['protocol'])}"
            svc_name = _h(svc["name"]) or "?"
            product = _h(svc["product"])
            version = _h(svc["version"])
            detail = " ".join(p for p in (product, version) if p)
            svc_line = f"{label} — {svc_name}" + (f" ({detail})" if detail else "")
            parts.append(f'<div class="service">{svc_line}</div>')
            findings = svc["findings"]
            if not findings:
                parts.append('<p class="empty">No findings.</p>')
                continue
            parts.append("<table>")
            parts.append(
                "<tr><th>CVE</th><th>severity</th><th>EPSS</th><th>KEV</th>"
                "<th>summary</th></tr>"
            )
            for f in findings:
                tier = _severity_tier_class(f.get("severity"))
                sev = _h(f.get("severity")) or "—"
                epss = f.get("epss_score")
                epss_cell = f"{epss:.2f}" if isinstance(epss, (int, float)) else "—"
                kev_cell = '<span class="badge kev">KEV</span>' if f.get("kev") else ""
                parts.append(
                    f'<tr class="{tier}">'
                    f"<td>{_h(f.get('cve_id'))}</td>"
                    f"<td>{sev}</td>"
                    f"<td>{epss_cell}</td>"
                    f"<td>{kev_cell}</td>"
                    f"<td>{_h(f.get('summary'))}</td>"
                    "</tr>"
                )
            parts.append("</table>")
        parts.append("</section>")

    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts)


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

    `fmt` is one of ``json``, ``csv``, ``markdown``, or ``html``. `tag`, when set,
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
    if fmt == "html":
        return to_html(state)
    return json.dumps(state, indent=2, sort_keys=False)
