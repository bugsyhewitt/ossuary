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
  * ``sarif``    — a SARIF v2.1.0 (Static Analysis Results Interchange Format,
                   OASIS) document: one ``result`` per finding, one ``rule`` per
                   distinct CVE. This is the standard machine artifact that
                   GitHub code scanning, DefectDojo, Azure DevOps, and other
                   security platforms ingest natively, so a hunter can pipe an
                   engagement's actionable findings straight into the tooling
                   ecosystem. Like the other formats it reads off ``build_state``,
                   so it honours the same filters and priority order.
  * ``cyclonedx`` — a CycloneDX 1.5 SBOM (Software Bill of Materials) JSON
                   document. Each fingerprinted service becomes a ``component``
                   (with a stable ``bom-ref``, a ``cpe`` / ``purl`` package
                   identifier where derivable) and each finding becomes a
                   ``vulnerability`` whose ``affects[].ref`` points back at the
                   owning component's ``bom-ref`` — that back-reference is the
                   SBOM-to-findings link. Vulnerability ratings carry the CVSS
                   severity and the live EPSS / KEV signal rides along in
                   ``properties``. This is the standard machine artifact that
                   Dependency-Track, DefectDojo, and the wider supply-chain
                   tooling ingest natively, so a hunter can pipe an engagement's
                   discovered-component + matched-vulnerability inventory straight
                   into an SBOM pipeline. Like the other formats it reads off
                   ``build_state``, so it honours the same filters and priority
                   order.
  * ``spdx``     — an SPDX 2.3 SBOM (Software Package Data Exchange, ISO/IEC
                   5962:2021) JSON document — the second open SBOM standard
                   alongside CycloneDX. Each fingerprinted service becomes a
                   ``package`` (with a stable ``SPDXID``, ``versionInfo``, and a
                   ``cpe23Type`` / ``purl`` external reference where derivable),
                   the document ``DESCRIBES`` each package via a relationship,
                   and each finding becomes a ``SECURITY`` external reference on
                   its package pointing at the CVE's NVD detail page (the SPDX
                   2.3 idiom for attaching a vulnerability to a component, with
                   EPSS / KEV / severity in the ref comment). This is the
                   standard machine artifact SPDX-consuming supply-chain tools
                   ingest, so a hunter can pipe an engagement's component +
                   matched-vulnerability inventory into an SPDX pipeline. Like
                   the other formats it reads off ``build_state``, so it honours
                   the same filters and priority order.
  * ``grype-json`` — Grype's ``-o json`` output shape (the Anchore-ecosystem
                   counterpart to ``trivy-table``): a top-level ``matches`` array
                   with one entry per finding, each carrying a ``vulnerability``
                   block (id / dataSource / severity / urls / description /
                   cvss[] / fix / advisories[]), a ``matchDetails`` block (the
                   match method — ``cpe-match`` when nmap supplied a CPE,
                   otherwise ``exact-direct-match``), and an ``artifact`` block
                   (the discovered service — name, version, type=``binary``,
                   locations[], cpes[], purl). Byte-recognisable to every Grype
                   consumer (the Grype GitHub Action, Anchore Enterprise,
                   Harbor, DefectDojo's Grype parser) so an engagement's
                   findings drop into the same downstream pipeline operators
                   already tune for Grype output. KEV rides as a CISA-KEV
                   advisory entry, EPSS as a ``properties`` vendor extension.
                   Like the other formats it reads off ``build_state``, so it
                   honours the same filters and priority order.
  * ``trivy-table`` — a Trivy-style text-table report (aquasecurity/trivy's
                   wire-format output): one per-target section per discovered
                   service, with Trivy's familiar Unicode-box-drawn table,
                   upper-case severity bucketing, and ``Total: N (UNKNOWN: a,
                   LOW: b, MEDIUM: c, HIGH: d, CRITICAL: e)`` summary line.
                   Byte-recognisable in a workflow already tuned for Trivy
                   output (terminal viewing, log scraping, CI annotation).
                   KEV / EPSS ride as inline ``[KEV]`` / ``[EPSS=0.95]``
                   markers in the Title cell rather than as extra columns
                   that would break the recognisable layout. Like the other
                   formats it reads off ``build_state``, so it honours the
                   same filters and priority order.
  * ``vex``      — a standalone OpenVEX (Vulnerability Exploitability eXchange)
                   JSON document. One ``statement`` per finding declares the
                   matched ``vulnerability`` (the CVE) ``affected`` on the
                   ``products`` it was found on (each product carries an ``@id``
                   service location and, where known, a ``cpe`` identifier). This
                   is the inverse of the suppression-import path (``dump --vex``):
                   export emits the triage worksheet a hunter edits — flipping
                   statements to ``not_affected`` / ``fixed`` as they rule findings
                   out — and feeds back in to suppress the cleared rows. The
                   emitted shape round-trips through ``ossuary.vex.parse``. Like
                   the other formats it reads off ``build_state``, so it honours
                   the same filters and priority order.
  * ``jira``     — an issue-tracker import CSV: one row per finding, shaped as a
                   ticket (``Summary`` title, rich ``Description``, mapped
                   ``Priority``, ``Labels``) rather than the raw inventory the
                   plain ``csv`` format emits. Both Jira's CSV importer and
                   Linear's CSV importer map these columns straight onto issue
                   fields, so a hunter can turn an engagement's actionable
                   findings into a triage backlog without retyping. It is
                   finding-centric (a service with no finding produces no row,
                   like SARIF) and reads off ``build_state``, so it honours the
                   same filters and priority order.

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

Recency filtering (``since`` / ``until``) trims the export to the findings whose
``matched_at`` timestamp falls inside a scan-time window. ``cruise`` / ``watch``
re-scan the same engagement over time, so after a fresh pass a hunter wants
"only the findings recorded since DATE" — the vulnerability-surface slice for a
window rather than the whole history. Both bounds are inclusive and either may
be given alone (open-ended on the other side). A bare ``YYYY-MM-DD`` ``until`` is
extended to end-of-day so a calendar day includes that day's timestamps. Like
the actionability filters, recency filtering drops findings with no recorded
``matched_at`` once a bound is set and prunes services / assets left empty; with
neither bound set the export is unchanged.
"""

from __future__ import annotations

import csv
import html
import io
import json
import sqlite3
from pathlib import Path
from urllib.parse import quote

from . import __version__, db, tags
from .vex import VexSuppressions
from .vex import load as vex_load

SUPPORTED_FORMATS = (
    "json",
    "csv",
    "markdown",
    "html",
    "sarif",
    "jira",
    "cyclonedx",
    "spdx",
    "vex",
    "cdx-vex",
    "trivy-table",
    "grype-json",
)

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
    "exploit",
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


def _normalise_until(value: str | None) -> str | None:
    """Normalise an ``until`` bound so a bare calendar day is inclusive.

    ``matched_at`` is stored as ``YYYY-MM-DD HH:MM:SS`` (sqlite ``datetime('now')``).
    A bare ``YYYY-MM-DD`` upper bound would, under a plain lexicographic compare,
    exclude that same day's timestamps (``"2026-05-29 12:00:00" > "2026-05-29"``).
    Extend such a bound to that day's last second so ``--until DATE`` includes all
    of DATE. A value that already carries a time component is returned unchanged.
    """
    if value is None:
        return None
    text = value.strip()
    # A bare date is exactly 10 chars (YYYY-MM-DD) with no time/space component.
    if len(text) == 10 and text[4] == "-" and text[7] == "-":
        return text + " 23:59:59"
    return text


def _finding_in_window(
    finding: dict,
    since: str | None,
    until: str | None,
) -> bool:
    """Return True when a finding's ``matched_at`` falls inside [since, until].

    Both bounds are inclusive and optional. ``matched_at`` is an ISO-8601-ish
    ``YYYY-MM-DD HH:MM:SS`` string, so lexicographic comparison orders it
    correctly. A finding with no ``matched_at`` is excluded once either bound is
    set (consistent with the actionability filters excluding missing signal).
    """
    if since is None and until is None:
        return True
    matched_at = finding.get("matched_at")
    if not matched_at:
        return False
    if since is not None and matched_at < since:
        return False
    if until is not None and matched_at > until:
        return False
    return True


def _finding_is_actionable(
    finding: dict,
    min_epss: float | None,
    min_severity: float | None,
    kev_only: bool,
    since: str | None = None,
    until: str | None = None,
) -> bool:
    """Return True when a finding clears every supplied actionability threshold.

    With no thresholds the finding always passes. ``kev_only`` requires KEV=1.
    ``min_epss`` requires a present EPSS score >= the floor (a finding with no
    EPSS score is excluded once an EPSS floor is set). ``min_severity`` requires
    a parseable severity >= the floor (un-parseable / blank severities are
    excluded once a severity floor is set). ``since`` / ``until`` bound the
    finding's ``matched_at`` recency window (both inclusive; a finding with no
    ``matched_at`` is excluded once either bound is set).
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
    if not _finding_in_window(finding, since, until):
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


def _finding_identifiers(ip: str | None, svc: dict, finding_location: str) -> set[str]:
    """Collect the strings a VEX product scope may match a finding against.

    A scoped VEX statement lists product identifiers; a finding is in scope when
    any of its locating strings — the asset ip, its ``ip:proto/port`` service
    location, or the service CPE — matches one. Blank values are dropped.
    """
    ids: set[str] = set()
    if ip:
        ids.add(ip)
    if finding_location:
        ids.add(finding_location)
    cpe = svc.get("cpe")
    if cpe:
        ids.add(str(cpe))
    return ids


def build_state(
    conn: sqlite3.Connection,
    tag: str | None = None,
    *,
    min_epss: float | None = None,
    min_severity: float | None = None,
    kev_only: bool = False,
    since: str | None = None,
    until: str | None = None,
    sort_by_priority: bool = False,
    vex: VexSuppressions | None = None,
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

    `since` / `until` are recency bounds on each finding's `matched_at`
    timestamp (both inclusive; either may be given alone). When either is set,
    findings recorded outside the window — and those with no `matched_at` — are
    dropped, and empty services / assets are pruned, exactly like the
    actionability filters. A bare `YYYY-MM-DD` `until` covers all of that day.

    When `sort_by_priority` is set, each service's findings are reordered
    KEV-first, then by descending EPSS, descending numeric severity, and finally
    CVE id — the same triage order `match-cves` prints — so the highest-signal
    findings lead. When unset, findings keep their alphabetical-by-CVE-id order.

    `vex`, when given, is a parsed VEX suppression index (see `ossuary.vex`).
    Findings whose CVE has been ruled `not_affected` / `fixed` for the finding's
    location are dropped — the triage-already-cleared rows are hidden without
    deleting them from the DB. Suppression composes with every other filter and,
    like them, prunes services / assets left with no surviving finding.
    """
    until = _normalise_until(until)
    since = since.strip() if since is not None else None
    filtering = (
        min_epss is not None
        or min_severity is not None
        or kev_only
        or since is not None
        or until is not None
        or vex is not None
    )
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
                "exploit, matched_at FROM findings WHERE service_id = ? "
                "ORDER BY cve_id",
                (svc["id"],),
            ).fetchall()
            findings_out = [dict(f) for f in findings]
            if filtering:
                findings_out = [
                    f
                    for f in findings_out
                    if _finding_is_actionable(
                        f, min_epss, min_severity, kev_only, since, until
                    )
                ]
                if vex is not None:
                    location = f"{asset['ip']}:{svc['protocol']}/{svc['port']}"
                    svc_view = {"cpe": svc["cpe"]}
                    identifiers = _finding_identifiers(
                        asset["ip"], svc_view, location
                    )
                    findings_out = [
                        f
                        for f in findings_out
                        if not vex.is_suppressed(
                            f.get("cve_id"), identifiers=identifiers
                        )
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
                        "exploit": f.get("exploit"),
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


# --------------------------------------------------------------------------
# SARIF v2.1.0 export (POST_V01 Rank 14)
# --------------------------------------------------------------------------

# SARIF maps a numeric CVSS base score to one of four ordered severity levels.
# ossuary additionally surfaces EPSS / KEV as result properties, but the SARIF
# `level` is the field most consumers (GitHub code scanning et al.) key off, so
# we derive it from the live signal: a KEV finding is always an `error`
# regardless of (often blank, post-NIST-retreat) CVSS, then numeric severity
# tiers, then `warning` as the floor for an un-scored finding.
def _sarif_level(finding: dict) -> str:
    """Map a finding to a SARIF result level (error/warning/note).

    KEV (confirmed exploited) is always ``error``. Otherwise the numeric CVSS
    severity drives it: >= 7.0 -> ``error``, >= 4.0 -> ``warning``, a parseable
    lower score -> ``note``. A blank / non-numeric severity with no KEV signal
    falls back to ``warning`` (the SARIF default) rather than silently sinking
    to ``note`` — an un-triaged finding shouldn't read as low-importance.
    """
    if finding.get("kev"):
        return "error"
    sev = _parse_severity(finding.get("severity"))
    if sev is None:
        return "warning"
    if sev >= 7.0:
        return "error"
    if sev >= 4.0:
        return "warning"
    return "note"


def _sarif_results_and_rules(state: dict) -> tuple[list[dict], list[dict]]:
    """Build the SARIF ``results`` list and the de-duplicated ``rules`` list.

    One ``result`` is emitted per finding (carrying its host:port location and
    EPSS / KEV / severity as result properties); one ``rule`` is emitted per
    distinct CVE id, so a CVE matched on several hosts contributes a single rule
    referenced by ``ruleId``. Rules are ordered by first appearance and results
    follow the same per-host / per-service / per-finding walk the other formats
    use, so the priority ordering (when requested) is preserved.
    """
    results: list[dict] = []
    rules: list[dict] = []
    rule_index: dict[str, int] = {}

    for asset in state["assets"]:
        ip = asset["ip"]
        host = asset.get("hostname")
        host_label = f"{ip} ({host})" if host else ip
        for svc in asset["services"]:
            port = svc["port"]
            protocol = svc["protocol"]
            location_uri = f"{ip}:{protocol}/{port}"
            product = svc.get("product")
            version = svc.get("version")
            svc_detail = " ".join(p for p in (product, version) if p)
            for f in svc["findings"]:
                cve_id = f.get("cve_id") or "UNKNOWN"
                summary = f.get("summary") or ""
                # Register a rule the first time we see this CVE.
                if cve_id not in rule_index:
                    rule_index[cve_id] = len(rules)
                    rule: dict = {
                        "id": cve_id,
                        "name": cve_id,
                        "shortDescription": {"text": cve_id},
                        "helpUri": (
                            f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                            if cve_id.upper().startswith("CVE-")
                            else None
                        ),
                    }
                    if summary:
                        rule["fullDescription"] = {"text": summary}
                    # Drop a None helpUri rather than emit a null.
                    if rule["helpUri"] is None:
                        del rule["helpUri"]
                    rules.append(rule)

                msg_target = svc_detail or f"{protocol}/{port}"
                message = (
                    f"{cve_id} on {host_label} ({msg_target})"
                    + (f": {summary}" if summary else "")
                )
                properties: dict = {
                    "ip": ip,
                    "port": port,
                    "protocol": protocol,
                    "kev": bool(f.get("kev")),
                }
                if host:
                    properties["hostname"] = host
                if product:
                    properties["product"] = product
                if version:
                    properties["version"] = version
                if f.get("epss_score") is not None:
                    properties["epss_score"] = f["epss_score"]
                if f.get("severity") not in (None, ""):
                    properties["severity"] = f["severity"]
                if f.get("source"):
                    properties["source"] = f["source"]

                results.append(
                    {
                        "ruleId": cve_id,
                        "ruleIndex": rule_index[cve_id],
                        "level": _sarif_level(f),
                        "message": {"text": message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": location_uri}
                                }
                            }
                        ],
                        "properties": properties,
                    }
                )
    return results, rules


def to_sarif(state: dict) -> str:
    """Serialise the engagement state as a SARIF v2.1.0 document.

    Emits a single run by the ``ossuary`` tool: one ``result`` per finding and
    one ``rule`` per distinct CVE. The document validates against the SARIF
    v2.1.0 schema and is ingestible by GitHub code scanning, DefectDojo, and the
    wider security-tooling ecosystem. An empty engagement still yields a valid
    document with an empty ``results`` array.
    """
    results, rules = _sarif_results_and_rules(state)
    sarif = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ossuary",
                        "informationUri": "https://github.com/bugsyhewitt/ossuary",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=False)


# --------------------------------------------------------------------------
# Issue-tracker import CSV export (Jira / Linear)
# --------------------------------------------------------------------------

# Columns for the issue-tracker import CSV, in emission order. The first four
# are the ones Jira's CSV importer and Linear's CSV importer map directly onto
# issue fields (Summary -> title, Description -> body, Priority -> priority,
# Labels -> labels); the remainder ride along as custom fields / extra columns
# so the triage context isn't lost. This is a ticket-shaped view, distinct from
# the raw-inventory FLAT_COLUMNS the plain `csv` format emits.
JIRA_COLUMNS = [
    "Summary",
    "Description",
    "Priority",
    "Labels",
    "Component",
    "CVE",
    "EPSS",
    "KEV",
    "Severity",
    "Host",
    "Port",
]


def _jira_priority(finding: dict) -> str:
    """Map a finding's live exploitation signal to a Jira/Linear priority name.

    Uses the same KEV-first / EPSS / numeric-severity signal the rest of ossuary
    triages on, mapped onto the default Jira priority scheme (which Linear's CSV
    importer also recognises): a KEV (confirmed-exploited) finding is always
    ``Highest``; otherwise EPSS or numeric CVSS — whichever is hotter — drives it
    (>= 0.5 EPSS or >= 7.0 CVSS -> ``High``, >= 0.1 EPSS or >= 4.0 CVSS ->
    ``Medium``), with an un-scored / cold finding defaulting to ``Low``.
    """
    if finding.get("kev"):
        return "Highest"
    epss = finding.get("epss_score")
    sev = _parse_severity(finding.get("severity"))
    if (epss is not None and epss >= 0.5) or (sev is not None and sev >= 7.0):
        return "High"
    if (epss is not None and epss >= 0.1) or (sev is not None and sev >= 4.0):
        return "Medium"
    return "Low"


def _jira_rows(state: dict) -> list[dict]:
    """Flatten the nested engagement state to one issue-shaped dict per finding.

    Finding-centric: a service with no findings yields no row (the format is a
    triage backlog of vulnerabilities, not an asset inventory). Each row carries
    a human ``Summary`` title, a multi-line ``Description`` with the triage
    context, a mapped ``Priority``, and ``;``-joined ``Labels`` (the host's tags
    plus ``kev`` when confirmed-exploited).
    """
    rows: list[dict] = []
    for asset in state["assets"]:
        ip = asset["ip"]
        host = asset.get("hostname")
        host_label = f"{ip} ({host})" if host else ip
        asset_tags = list(asset.get("tags") or [])
        for svc in asset["services"]:
            port = svc["port"]
            protocol = svc["protocol"]
            product = svc.get("product")
            version = svc.get("version")
            svc_detail = " ".join(p for p in (product, version) if p)
            component = svc_detail or f"{protocol}/{port}"
            for f in svc["findings"]:
                cve_id = f.get("cve_id") or "UNKNOWN"
                summary_text = f.get("summary") or ""
                epss = f.get("epss_score")
                epss_cell = f"{epss:.2f}" if isinstance(epss, (int, float)) else ""
                kev = bool(f.get("kev"))
                severity = f.get("severity") or ""

                title = f"{cve_id} on {host_label}" + (
                    f" ({svc_detail})" if svc_detail else f" ({protocol}/{port})"
                )
                desc_lines = [
                    f"CVE: {cve_id}",
                    f"Host: {host_label}",
                    f"Service: {protocol}/{port}"
                    + (f" — {svc_detail}" if svc_detail else ""),
                    f"Severity (CVSS): {severity or '—'}",
                    f"EPSS: {epss_cell or '—'}",
                    f"KEV (CISA confirmed-exploited): {'yes' if kev else 'no'}",
                ]
                if f.get("source"):
                    desc_lines.append(f"Source: {f['source']}")
                if summary_text:
                    desc_lines.append("")
                    desc_lines.append(summary_text)
                description = "\n".join(desc_lines)

                labels = list(asset_tags)
                if kev:
                    labels.append("kev")

                rows.append(
                    {
                        "Summary": title,
                        "Description": description,
                        "Priority": _jira_priority(f),
                        "Labels": ";".join(labels),
                        "Component": component,
                        "CVE": cve_id,
                        "EPSS": epss_cell,
                        "KEV": "yes" if kev else "no",
                        "Severity": severity,
                        "Host": host_label,
                        "Port": f"{protocol}/{port}",
                    }
                )
    return rows


def to_jira(state: dict) -> str:
    """Serialise the engagement state as an issue-tracker import CSV.

    One row per finding, shaped as a ticket (``Summary`` / ``Description`` /
    ``Priority`` / ``Labels`` …) so Jira's and Linear's CSV importers map the
    rows straight onto issue fields. Finding-centric: services with no findings
    produce no rows. An empty engagement still yields a valid CSV (header only).
    """
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(JIRA_COLUMNS)
    for row in _jira_rows(state):
        writer.writerow([_cell(row.get(col)) for col in JIRA_COLUMNS])
    return buf.getvalue()


# --------------------------------------------------------------------------
# CycloneDX 1.5 SBOM export (SBOM-linked findings)
# --------------------------------------------------------------------------

# CycloneDX maps a numeric CVSS base score to one of five named severities. We
# bucket the same way the `stats` / HTML tiering does so a hunter reads one
# consistent severity taxonomy across every surface; a blank / non-numeric score
# (common post-NIST-retreat) is reported as the CycloneDX `unknown` severity
# rather than silently dropped.
def _cyclonedx_severity(value) -> str:
    """Map a finding's severity to a CycloneDX rating severity label."""
    sev = _parse_severity(value)
    if sev is None:
        return "unknown"
    if sev >= 9.0:
        return "critical"
    if sev >= 7.0:
        return "high"
    if sev >= 4.0:
        return "medium"
    if sev > 0.0:
        return "low"
    return "none"


def _bom_ref(ip: str, protocol, port) -> str:
    """Stable component bom-ref for a service: ``ip:proto/port``.

    Mirrors the SARIF location URI so the two machine artifacts locate a service
    the same way, and is unique per service row (the schema's UNIQUE key).
    """
    return f"{ip}:{protocol}/{port}"


def _purl(product, version) -> str | None:
    """Best-effort Package URL (purl) for a discovered service component.

    A purl is the supply-chain ecosystem's portable package identifier. ossuary
    discovers *generic* software at the network layer (not a language-ecosystem
    package), so we emit a ``pkg:generic/<product>@<version>`` purl — the purl
    spec's escape hatch for software with no specific package type. Returns None
    when there's no product to name (no usable identifier).
    """
    if not product:
        return None
    name = quote(str(product), safe="")
    if version:
        return f"pkg:generic/{name}@{quote(str(version), safe='')}"
    return f"pkg:generic/{name}"


def _cyclonedx_components_and_vulns(
    state: dict,
) -> tuple[list[dict], list[dict]]:
    """Build the CycloneDX ``components`` and ``vulnerabilities`` lists.

    One ``component`` is emitted per service (every fingerprinted host:port),
    carrying a stable ``bom-ref``, the service name/version, and a ``cpe`` /
    ``purl`` package identifier where derivable. One ``vulnerability`` is emitted
    per finding; its ``affects[].ref`` points back at the owning component's
    ``bom-ref`` — the SBOM-to-findings link. The CVSS severity rides in
    ``ratings`` and the live EPSS / KEV signal in ``properties``. Components and
    vulnerabilities follow the same per-host / per-service / per-finding walk the
    other formats use, so the priority ordering (when requested) is preserved.
    """
    components: list[dict] = []
    vulnerabilities: list[dict] = []

    for asset in state["assets"]:
        ip = asset["ip"]
        host = asset.get("hostname")
        for svc in asset["services"]:
            port = svc["port"]
            protocol = svc["protocol"]
            ref = _bom_ref(ip, protocol, port)
            name = svc.get("product") or svc.get("name") or f"{protocol}/{port}"
            component: dict = {
                "type": "application",
                "bom-ref": ref,
                "name": str(name),
            }
            if svc.get("version"):
                component["version"] = str(svc["version"])
            if svc.get("cpe"):
                component["cpe"] = str(svc["cpe"])
            purl = _purl(svc.get("product"), svc.get("version"))
            if purl:
                component["purl"] = purl
            host_label = f"{ip} ({host})" if host else ip
            component["properties"] = [
                {"name": "ossuary:host", "value": host_label},
                {"name": "ossuary:port", "value": f"{protocol}/{port}"},
            ]
            components.append(component)

            for f in svc["findings"]:
                cve_id = f.get("cve_id") or "UNKNOWN"
                vuln: dict = {
                    "bom-ref": f"{ref}#{cve_id}",
                    "id": cve_id,
                    "affects": [{"ref": ref}],
                }
                if cve_id.upper().startswith("CVE-"):
                    vuln["source"] = {
                        "name": "NVD",
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    }
                if f.get("summary"):
                    vuln["description"] = str(f["summary"])
                sev = _parse_severity(f.get("severity"))
                rating: dict = {"severity": _cyclonedx_severity(f.get("severity"))}
                if sev is not None:
                    rating["score"] = sev
                    rating["method"] = "CVSSv3"
                vuln["ratings"] = [rating]
                props = [{"name": "ossuary:kev", "value": "true" if f.get("kev") else "false"}]
                if f.get("epss_score") is not None:
                    props.append(
                        {"name": "ossuary:epss", "value": f"{f['epss_score']}"}
                    )
                if f.get("source"):
                    props.append({"name": "ossuary:source", "value": str(f["source"])})
                vuln["properties"] = props
                vulnerabilities.append(vuln)

    return components, vulnerabilities


def to_cyclonedx(state: dict) -> str:
    """Serialise the engagement state as a CycloneDX 1.5 SBOM document.

    Emits a ``bomFormat: CycloneDX`` / ``specVersion: 1.5`` JSON document: one
    ``component`` per discovered service and one ``vulnerability`` per finding,
    each vulnerability linked back to its component via ``affects[].ref``. The
    document is ingestible by Dependency-Track, DefectDojo, and the wider
    supply-chain tooling ecosystem. An empty engagement still yields a valid
    document with empty ``components`` / ``vulnerabilities`` arrays.
    """
    components, vulnerabilities = _cyclonedx_components_and_vulns(state)
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [
                {
                    "vendor": "bugsyhewitt",
                    "name": "ossuary",
                    "version": __version__,
                }
            ],
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }
    return json.dumps(bom, indent=2, sort_keys=False)


# --------------------------------------------------------------------------
# SPDX 2.3 SBOM export (the ISO/IEC 5962:2021 companion to CycloneDX)
# --------------------------------------------------------------------------

# SPDX is the second of the two open SBOM standards (CycloneDX is the other),
# standardised as ISO/IEC 5962:2021 and required by the US executive-order
# software-supply-chain guidance. Where CycloneDX models a vulnerability as a
# first-class object, SPDX 2.3 attaches a vulnerability to its package via a
# `SECURITY` external reference (referenceCategory) pointing at the CVE's NVD
# record. We emit the tag-value-equivalent JSON shape: a document with
# creationInfo, one `package` per discovered service, a `DESCRIBES` relationship
# from the document to each package, and a `SECURITY`/`cpe23Type`/`purl` external
# reference list per package so a hunter's discovered-component + matched-CVE
# inventory drops into any SPDX-consuming supply-chain tool.

# Characters SPDX allows in an SPDXID after the mandatory `SPDXRef-` prefix:
# letters, digits, `.` and `-`. Everything else (`:`, `/`, spaces, …) is mapped
# to `-` so a service location like `10.10.0.5:tcp/80` yields a valid id.
_SPDX_ID_SAFE = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
)


def _spdx_id(suffix: str) -> str:
    """Build a schema-valid ``SPDXRef-<suffix>`` identifier.

    SPDX restricts the id alphabet to letters, digits, ``.`` and ``-``; any
    other character in ``suffix`` (``:`` / ``/`` / space …) is replaced with a
    ``-`` so a service location maps to a unique, valid SPDXID.
    """
    cleaned = "".join(c if c in _SPDX_ID_SAFE else "-" for c in suffix)
    return f"SPDXRef-{cleaned}"


def _spdx_external_refs(svc: dict, findings: list[dict]) -> list[dict]:
    """Build a package's SPDX 2.3 ``externalRefs`` list.

    Carries the package identifiers SPDX recognises — a ``cpe23Type`` ref for a
    service CPE and a ``purl`` ref for the derived Package URL — plus one
    ``SECURITY`` / ``cve`` reference per finding, the SPDX 2.3 way of attaching a
    matched vulnerability to a package (pointing at the CVE's NVD detail page).
    """
    refs: list[dict] = []
    cpe = svc.get("cpe")
    if cpe:
        refs.append(
            {
                "referenceCategory": "SECURITY",
                "referenceType": "cpe23Type",
                "referenceLocator": str(cpe),
            }
        )
    purl = _purl(svc.get("product"), svc.get("version"))
    if purl:
        refs.append(
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        )
    for f in findings:
        cve_id = f.get("cve_id") or "UNKNOWN"
        if cve_id.upper().startswith("CVE-"):
            locator = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        else:
            locator = cve_id
        ref = {
            "referenceCategory": "SECURITY",
            "referenceType": "cve",
            "referenceLocator": locator,
        }
        comment_bits = [cve_id]
        sev = f.get("severity")
        if sev not in (None, ""):
            comment_bits.append(f"severity={sev}")
        if f.get("epss_score") is not None:
            comment_bits.append(f"epss={f['epss_score']}")
        if f.get("kev"):
            comment_bits.append("kev")
        ref["comment"] = " ".join(comment_bits)
        refs.append(ref)
    return refs


def _spdx_packages_and_relationships(
    state: dict,
    doc_spdxid: str,
) -> tuple[list[dict], list[dict]]:
    """Build the SPDX ``packages`` and ``relationships`` lists.

    One ``package`` is emitted per service (every fingerprinted host:port),
    carrying a stable SPDXID derived from its ``ip:proto/port`` location, the
    service name / version, and the external references (CPE / purl / per-finding
    CVE). One ``DESCRIBES`` relationship links the document to each package — the
    SPDX way of declaring the document's described subjects. Packages follow the
    same per-host / per-service walk the other formats use, so any requested
    priority ordering is preserved.
    """
    packages: list[dict] = []
    relationships: list[dict] = []

    for asset in state["assets"]:
        ip = asset["ip"]
        host = asset.get("hostname")
        for svc in asset["services"]:
            port = svc["port"]
            protocol = svc["protocol"]
            ref = _bom_ref(ip, protocol, port)
            spdxid = _spdx_id(ref)
            name = svc.get("product") or svc.get("name") or f"{protocol}/{port}"
            package: dict = {
                "SPDXID": spdxid,
                "name": str(name),
                # SPDX requires these two fields on every package; ossuary does
                # not assert anything about download source or licensing of a
                # network-discovered service, so both are the spec's NOASSERTION.
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
            if svc.get("version"):
                package["versionInfo"] = str(svc["version"])
            host_label = f"{ip} ({host})" if host else ip
            package["comment"] = (
                f"discovered service on {host_label} {protocol}/{port}"
            )
            ext_refs = _spdx_external_refs(svc, svc["findings"])
            if ext_refs:
                package["externalRefs"] = ext_refs
            packages.append(package)
            relationships.append(
                {
                    "spdxElementId": doc_spdxid,
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": spdxid,
                }
            )

    return packages, relationships


def to_spdx(state: dict) -> str:
    """Serialise the engagement state as an SPDX 2.3 SBOM (JSON) document.

    Emits an ``spdxVersion: SPDX-2.3`` document: one ``package`` per discovered
    service and a ``DESCRIBES`` relationship from the document to each package.
    Each package carries its CPE / purl identifier and one ``SECURITY`` external
    reference per matched CVE — the SPDX 2.3 way of attaching a vulnerability to
    a component. The document is ingestible by SPDX-consuming supply-chain tools
    (the ISO/IEC 5962:2021 standard alongside CycloneDX). An empty engagement
    still yields a valid document with empty ``packages`` / ``relationships``
    arrays.
    """
    doc_spdxid = "SPDXRef-DOCUMENT"
    packages, relationships = _spdx_packages_and_relationships(state, doc_spdxid)
    spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": doc_spdxid,
        "name": "ossuary-engagement",
        "documentNamespace": (
            "https://github.com/bugsyhewitt/ossuary/spdx/ossuary-engagement"
        ),
        "creationInfo": {
            "creators": [f"Tool: ossuary-{__version__}"],
            # A fixed sentinel keeps the document byte-stable for tests; SPDX
            # requires the field but accepts any valid ISO-8601 instant.
            "created": "1970-01-01T00:00:00Z",
        },
        "packages": packages,
        "relationships": relationships,
    }
    return json.dumps(spdx, indent=2, sort_keys=False)


# --------------------------------------------------------------------------
# OpenVEX export (standalone VEX document — the inverse of the import path)
# --------------------------------------------------------------------------

# The OpenVEX status a freshly-discovered, matched finding carries. A finding in
# the DB is, by construction, a vulnerability that *matched* a discovered service
# — i.e. the product is present and the CVE applies until a human triages it
# away. So export defaults every statement to `affected`; the hunter edits the
# document, flipping the ones they rule out to `not_affected` / `fixed`, and
# feeds it back through `dump --vex` (which suppresses exactly those two
# statuses). `affected` is one of the spec's four statuses and round-trips
# cleanly through `ossuary.vex.parse` (it's accepted but contributes no
# suppression — correct for an un-triaged finding).
_VEX_EXPORT_STATUS = "affected"


def _vex_product(ip: str, protocol, port, cpe) -> dict:
    """Build one OpenVEX ``product`` entry locating a finding's service.

    Carries an ``@id`` of the ``ip:proto/port`` service location (the same
    locator SARIF / SBOM use) so a scoped statement matches the finding's
    location on re-import, plus a ``cpe`` identifier under ``identifiers`` when
    the service has one — the two strings ``ossuary.vex`` extracts to scope a
    suppression. The shape is exactly what ``vex._product_identifiers`` parses,
    so an exported document round-trips through the import path.
    """
    location = _bom_ref(ip, protocol, port)
    product: dict = {"@id": location}
    if cpe:
        product["identifiers"] = {"cpe": str(cpe)}
    return product


def _vex_statements(state: dict) -> list[dict]:
    """Build the OpenVEX ``statements`` list — one statement per finding.

    Each statement declares the matched ``vulnerability`` (the CVE, as the
    spec's ``{"name": ...}`` object), an ``affected`` ``status`` (the un-triaged
    default; the hunter edits these), and the ``products`` the CVE was found on
    (the service location + CPE). A finding's free-text summary rides along as
    ``status_notes`` so the triage context isn't lost in the worksheet.
    Statements follow the same per-host / per-service / per-finding walk the
    other formats use, so any requested priority ordering is preserved.
    """
    statements: list[dict] = []
    for asset in state["assets"]:
        ip = asset["ip"]
        for svc in asset["services"]:
            port = svc["port"]
            protocol = svc["protocol"]
            cpe = svc.get("cpe")
            product = _vex_product(ip, protocol, port, cpe)
            for f in svc["findings"]:
                cve_id = f.get("cve_id") or "UNKNOWN"
                statement: dict = {
                    "vulnerability": {"name": cve_id},
                    "status": _VEX_EXPORT_STATUS,
                    "products": [dict(product)],
                }
                summary = f.get("summary")
                if summary:
                    statement["status_notes"] = str(summary)
                statements.append(statement)
    return statements


def to_vex(state: dict) -> str:
    """Serialise the engagement state as a standalone OpenVEX JSON document.

    Emits an OpenVEX ``@context`` / ``@id`` document whose ``statements`` carry
    one ruling per finding — the matched CVE declared ``affected`` on the
    product (service location + CPE) it was found on. This is the inverse of the
    suppression-import path (``dump --vex``): export produces the triage
    worksheet a hunter edits down (flipping statements to ``not_affected`` /
    ``fixed`` as they rule findings out) and re-imports to suppress the cleared
    rows. The emitted shape round-trips through ``ossuary.vex.parse``. An empty
    engagement still yields a valid document with an empty ``statements`` array.
    """
    statements = _vex_statements(state)
    document = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://github.com/bugsyhewitt/ossuary/vex/ossuary-engagement",
        "author": f"ossuary-{__version__}",
        "role": "tool",
        # A fixed sentinel keeps the document byte-stable for tests; OpenVEX
        # requires the field but accepts any valid ISO-8601 instant.
        "timestamp": "1970-01-01T00:00:00Z",
        "version": 1,
        "statements": statements,
    }
    return json.dumps(document, indent=2, sort_keys=False)


# --------------------------------------------------------------------------
# CycloneDX VEX export (`--format cdx-vex`)
# --------------------------------------------------------------------------
#
# CycloneDX VEX is the CycloneDX-native counterpart to OpenVEX: a CycloneDX
# 1.5 document carrying the discovered services as ``components`` and each
# finding as a ``vulnerability`` *with an ``analysis`` block* recording the
# triage state — the field that turns a CycloneDX SBOM into a VEX. The status
# vocabulary is CycloneDX's own (``in_triage`` / ``exploitable`` /
# ``not_affected`` / ``false_positive`` / ``resolved`` / ``resolved_with_pedigree``)
# rather than OpenVEX's, so a hunter who is shipping into a CycloneDX-only
# pipeline (Dependency-Track, Anchore, JFrog Xray, the broader supply-chain
# ecosystem that prefers CycloneDX-native VEX over OpenVEX) gets the editable
# triage worksheet in the format their downstream consumer reads.
#
# The default emitted ``state`` is ``in_triage`` — every finding is un-triaged
# at export time, exactly the way the OpenVEX export emits ``affected``. The
# hunter flips entries to ``not_affected`` / ``false_positive`` / ``resolved``
# as they rule findings out; the edited document is the VEX deliverable that
# accompanies the SBOM in a supply-chain handoff. We do NOT round-trip this
# format back through ``ossuary.vex.parse`` (that path is OpenVEX-shaped); the
# cdx-vex document is an export-only artifact for downstream CycloneDX
# consumers, alongside the OpenVEX worksheet that ``--format vex`` emits for
# the in-house ``--vex`` suppression loop.

# CycloneDX VEX's default analysis state — the spec value for an untriaged
# finding. A hunter flips this to one of the clearing states as they triage.
_CDX_VEX_DEFAULT_STATE = "in_triage"


def to_cdx_vex(state: dict) -> str:
    """Serialise the engagement state as a CycloneDX 1.5 VEX document.

    Emits a ``bomFormat: CycloneDX`` / ``specVersion: 1.5`` JSON document
    carrying one ``component`` per discovered service and one ``vulnerability``
    per finding — the same SBOM shape ``--format cyclonedx`` emits — *with* an
    ``analysis`` block on every vulnerability whose ``state`` defaults to
    ``in_triage`` (CycloneDX's spec value for an untriaged finding). It is the
    CycloneDX-native counterpart to ``--format vex`` (OpenVEX): the editable
    triage worksheet a hunter ships into a Dependency-Track / Anchore /
    CycloneDX-consuming supply-chain pipeline, flipping each entry to
    ``not_affected`` / ``false_positive`` / ``resolved`` as they rule findings
    out. An empty engagement still yields a valid document with empty
    ``components`` / ``vulnerabilities`` arrays.
    """
    components, vulnerabilities = _cyclonedx_components_and_vulns(state)
    # Attach an `analysis` block to every vulnerability — the field that
    # distinguishes a CycloneDX VEX document from a plain CycloneDX SBOM.
    for v in vulnerabilities:
        v["analysis"] = {"state": _CDX_VEX_DEFAULT_STATE}
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [
                {
                    "vendor": "bugsyhewitt",
                    "name": "ossuary",
                    "version": __version__,
                }
            ],
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }
    return json.dumps(bom, indent=2, sort_keys=False)


# --------------------------------------------------------------------------
# Trivy-style table export (`--format trivy-table`)
# --------------------------------------------------------------------------
#
# Trivy (aquasecurity/trivy) is the de-facto-standard CLI vulnerability
# scanner in 2025-2026 CI pipelines, and its classic text-table output is the
# shape every SRE / AppSec engineer recognises at a glance. ossuary scans a
# different surface (network services rather than container layers / language
# manifests) but the data shape lines up: a "Target" is a discovered service
# (host:port + product), a "Library" is the product, a "Vulnerability" is the
# CVE, a "Severity" is the CVSS tier. Emitting in this familiar shape lets a
# hunter drop an engagement's findings into a workflow already tuned for
# Trivy output (terminal viewing, log scraping, CI annotation) without
# learning a new layout.
#
# We deliberately use Trivy's actual rendering — Unicode box-drawing
# (┌─┬─┐ │ ├─┼─┤ └─┴─┘), the per-target header + summary line, severity in
# upper-case, columns aligned to the widest cell — so the output is
# byte-recognisable, not a "looks-vaguely-like-Trivy" approximation. Pure
# Python text formatting, no new dependencies, reads off ``build_state`` so
# the same actionability filters / priority ordering / VEX suppression apply
# identically to every other format.
#
# KEV (CISA's Known Exploited Vulnerabilities catalog) and EPSS are
# ossuary-specific live-signal columns that Trivy's table doesn't carry; we
# fold them into the Title cell (``[KEV]`` prefix, ``[EPSS=0.95]`` suffix)
# rather than adding a sixth column that would break the recognisability.
# Trivy itself does the same kind of inline marker for its own status tags.

_TRIVY_COLUMNS = (
    "Library",
    "Vulnerability",
    "Severity",
    "Installed Version",
    "Fixed Version",
    "Title",
)

# Severity tiers, ordered the way Trivy summarises them
# (Total: N (UNKNOWN: a, LOW: b, MEDIUM: c, HIGH: d, CRITICAL: e)). Lower-case
# keys mirror the tiering the rest of the module uses (CycloneDX / stats /
# HTML); the printed labels are upper-case to match Trivy's wire format.
_TRIVY_SEVERITY_ORDER = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def _trivy_severity(value) -> str:
    """Map a finding's severity to a Trivy upper-case severity label.

    Uses the same numeric tiering the rest of ossuary triages on
    (``stats`` / HTML / CycloneDX) so a hunter reads one consistent severity
    taxonomy across every surface; a blank / non-numeric score (common
    post-NIST-retreat) is reported as ``UNKNOWN`` — the bucket Trivy itself
    uses for an un-scored advisory — rather than silently dropped.
    """
    sev = _parse_severity(value)
    if sev is None:
        return "UNKNOWN"
    if sev >= 9.0:
        return "CRITICAL"
    if sev >= 7.0:
        return "HIGH"
    if sev >= 4.0:
        return "MEDIUM"
    if sev > 0.0:
        return "LOW"
    return "UNKNOWN"


def _trivy_title(finding: dict) -> str:
    """Render the Title cell for a finding.

    Trivy's Title column carries the vulnerability's free-text summary. We
    additionally fold ossuary's live-signal columns (KEV / EPSS) into the
    cell as inline markers — Trivy itself uses the same kind of inline tag
    for its own status fields, so the convention is recognisable. KEV
    (confirmed-exploited) leads as a ``[KEV]`` prefix; EPSS exploit-
    probability rides as an ``[EPSS=0.95]`` suffix when known. An empty
    summary collapses to the markers alone, or to an empty string when
    neither marker fires.
    """
    parts: list[str] = []
    if finding.get("kev"):
        parts.append("[KEV]")
    summary = finding.get("summary") or ""
    if summary:
        parts.append(str(summary))
    epss = finding.get("epss_score")
    if isinstance(epss, (int, float)):
        parts.append(f"[EPSS={epss:.2f}]")
    return " ".join(parts)


def _trivy_targets(state: dict) -> list[dict]:
    """Group findings into Trivy-style targets — one per discovered service.

    A Trivy "target" is the scanned artifact (an image, a manifest, a
    filesystem path). ossuary's equivalent is the discovered service: each
    host:port + product becomes one target. The target label mirrors how a
    hunter reads the inventory — ``<host> (<ip>):<port>/<protocol>
    (<product> <version>)`` — so the same identifier from a Trivy run is
    immediately legible here. Targets follow the same per-host / per-service
    walk every other format uses, so any requested priority ordering is
    preserved.
    """
    targets: list[dict] = []
    for asset in state["assets"]:
        ip = asset["ip"]
        host = asset.get("hostname")
        host_label = f"{host} ({ip})" if host else ip
        for svc in asset["services"]:
            port = svc["port"]
            protocol = svc["protocol"]
            product = svc.get("product")
            version = svc.get("version")
            svc_detail = " ".join(p for p in (product, version) if p)
            target_label = f"{host_label}:{port}/{protocol}" + (
                f" ({svc_detail})" if svc_detail else ""
            )
            rows: list[dict] = []
            for f in svc["findings"]:
                rows.append(
                    {
                        "Library": (product or svc.get("name") or f"{protocol}/{port}"),
                        "Vulnerability": f.get("cve_id") or "UNKNOWN",
                        "Severity": _trivy_severity(f.get("severity")),
                        "Installed Version": (version or ""),
                        # ossuary doesn't track patched-in versions yet; leave
                        # the column present (Trivy always renders it) but
                        # blank, the same way Trivy does for "no fix
                        # available" advisories.
                        "Fixed Version": "",
                        "Title": _trivy_title(f),
                    }
                )
            targets.append({"label": target_label, "rows": rows})
    return targets


def _trivy_summary_line(rows: list[dict]) -> str:
    """Render Trivy's per-target summary line (``Total: N (UNKNOWN: a, ...)``)."""
    counts = {tier: 0 for tier in _TRIVY_SEVERITY_ORDER}
    for row in rows:
        counts[row["Severity"]] += 1
    breakdown = ", ".join(f"{tier}: {counts[tier]}" for tier in _TRIVY_SEVERITY_ORDER)
    return f"Total: {len(rows)} ({breakdown})"


def _trivy_render_table(rows: list[dict]) -> list[str]:
    """Render a single target's rows as a Trivy-style box-drawn table.

    Column widths are sized to the widest cell (including the header) so
    the table renders aligned without word-wrap. Trivy uses Unicode
    box-drawing glyphs (``┌─┬─┐ │ ├─┼─┤ └─┴─┘``); we mirror that exactly
    so the output is byte-recognisable from a real Trivy run.
    """
    columns = list(_TRIVY_COLUMNS)
    widths = {col: len(col) for col in columns}
    for row in rows:
        for col in columns:
            widths[col] = max(widths[col], len(str(row[col])))

    def hline(left: str, mid: str, right: str) -> str:
        return (
            left
            + mid.join("─" * (widths[col] + 2) for col in columns)
            + right
        )

    def data_line(values: list[str]) -> str:
        cells = [f" {values[i].ljust(widths[columns[i]])} " for i in range(len(columns))]
        return "│" + "│".join(cells) + "│"

    return [
        hline("┌", "┬", "┐"),
        data_line(columns),
        hline("├", "┼", "┤"),
        *(data_line([str(row[col]) for col in columns]) for row in rows),
        hline("└", "┴", "┘"),
    ]


def to_trivy_table(state: dict) -> str:
    """Serialise the engagement state as a Trivy-style text-table report.

    Emits one per-target section per discovered service: a target header line
    (``<host> (<ip>):<port>/<protocol> (<product> <version>)``), a Trivy
    summary line (``Total: N (UNKNOWN: a, LOW: b, MEDIUM: c, HIGH: d,
    CRITICAL: e)``), and a Unicode-box-drawn table of the findings on that
    service — the exact shape ``trivy image`` / ``trivy fs`` print, so the
    output is byte-recognisable in a workflow already tuned for Trivy. KEV
    and EPSS ride as inline ``[KEV]`` / ``[EPSS=0.95]`` markers in the Title
    cell (Trivy's own convention for inline status tags) rather than as
    extra columns that would break the recognisable layout.

    Targets with no findings emit just the header + ``No vulnerabilities
    found`` (Trivy's own wording). An empty engagement still yields a valid
    single-line report.
    """
    targets = _trivy_targets(state)
    if not targets:
        # Trivy itself prints a brief "no input" line when given nothing;
        # mirror that so an empty DB produces a well-formed, non-empty
        # artifact rather than silence.
        return "ossuary: no targets in engagement\n"

    parts: list[str] = []
    for i, target in enumerate(targets):
        if i:
            parts.append("")  # blank line between targets
        parts.append(target["label"])
        parts.append("=" * len(target["label"]))
        if not target["rows"]:
            parts.append("Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)")
            parts.append("")
            parts.append("No vulnerabilities found")
            continue
        parts.append(_trivy_summary_line(target["rows"]))
        parts.append("")
        parts.extend(_trivy_render_table(target["rows"]))
    return "\n".join(parts) + "\n"


# --------------------------------------------------------------------------
# Grype JSON export (`--format grype-json`)
# --------------------------------------------------------------------------
#
# Grype (anchore/grype) is the de-facto Anchore-ecosystem CLI vulnerability
# scanner — Syft produces an SBOM, Grype matches CVEs against it. Its
# default `-o json` output is the standard machine artifact every Grype-aware
# downstream consumer reads: the Grype GitHub Action posts it as PR
# annotations, Anchore Enterprise / Harbor ingest it for policy gates, and
# `grype-db` / DefectDojo / many home-grown triage pipelines parse it
# natively. R31 shipped `trivy-table` for the Trivy ecosystem; `grype-json`
# is its Anchore-ecosystem counterpart, so a hunter can drop ossuary's
# findings into either CI scanner's downstream workflow without learning a
# new layout.
#
# The shape is byte-recognisable to Grype's parser: a top-level `matches`
# array (one entry per finding) carrying `vulnerability` (id, dataSource,
# severity, urls, description, cvss[], fix), `relatedVulnerabilities` (empty
# — ossuary doesn't track CVE aliases), `matchDetails` (the match method —
# `cpe-match` when nmap supplied a CPE, otherwise `exact-direct-match`),
# and `artifact` (the discovered service — name, version, type=`binary`,
# locations[], cpes[], purl). The top-level wrapper also carries `source`
# (one entry per discovered asset — Grype scans a single source per run but
# ossuary's source is the whole engagement DB, so we use the document's
# `directory`-shaped source), `distro` (empty — ossuary doesn't fingerprint
# the host OS), and `descriptor` (`ossuary`, the running version, and the
# DB-file equivalent of a Grype configuration block) so the document is
# self-describing.
#
# KEV (CISA's Known Exploited Vulnerabilities catalog) and EPSS are
# ossuary-specific live-signal columns Grype's own output doesn't carry —
# they ride in a Grype-permitted vendor extension (`matchDetails[].fix` and
# `vulnerability.advisories[]` are the slots Grype already reserves for
# downstream-tool metadata). We use `vulnerability.advisories` for the KEV
# entry (an actual advisory link to CISA's KEV catalogue page) and a
# top-level `properties` block on each match for the EPSS score, since
# Grype consumers that key off the live signal can find it in the same
# spot they'd find any other vendor-extended field. Severity bucketing
# uses Grype's own capitalisation (`Critical` / `High` / `Medium` / `Low`
# / `Negligible` / `Unknown`) — the exact tokens Grype itself emits — so
# downstream filters that key off severity strings keep working.

_GRYPE_SEVERITY_ORDER = (
    "Unknown", "Negligible", "Low", "Medium", "High", "Critical",
)


def _grype_severity(value) -> str:
    """Map a finding's free-text severity to a Grype capitalised label.

    Grype itself reports severities as ``Critical`` / ``High`` / ``Medium`` /
    ``Low`` / ``Negligible`` / ``Unknown`` — the title-case tokens its
    downstream consumers (the Grype GitHub Action, Anchore Enterprise,
    DefectDojo's Grype parser) key off. We use the same numeric tiering the
    rest of ossuary triages on (stats / HTML / CycloneDX / trivy-table) so a
    hunter reads one consistent severity taxonomy across every surface; a
    blank / non-numeric score (common post-NIST-retreat) becomes
    ``Unknown`` — the bucket Grype itself uses for an un-scored advisory —
    rather than being silently dropped.
    """
    sev = _parse_severity(value)
    if sev is None:
        return "Unknown"
    if sev >= 9.0:
        return "Critical"
    if sev >= 7.0:
        return "High"
    if sev >= 4.0:
        return "Medium"
    if sev > 0.0:
        return "Low"
    return "Negligible"


def _grype_purl(product: str | None, version: str | None) -> str | None:
    """Build a ``pkg:generic`` purl for a discovered service.

    Grype's ``artifact.purl`` is the canonical handle every downstream
    consumer (Anchore Enterprise, Harbor, dependency-track-Grype) keys off
    when joining match data back to an SBOM. ossuary scans network
    services rather than language manifests, so the ecosystem is
    ``generic`` — the same purl ecosystem ``cyclonedx`` / ``spdx`` already
    emit, so a hunter can join a Grype consumer to an ossuary-emitted SBOM
    by the purl. A service with no product yields no purl (Grype itself
    omits the field rather than emitting an empty string).
    """
    if not product:
        return None
    if version:
        return f"pkg:generic/{product}@{version}"
    return f"pkg:generic/{product}"


def _grype_match(finding: dict, asset: dict, service: dict) -> dict:
    """Render one finding as a Grype ``matches[]`` entry.

    Mirrors Grype's ``-o json`` shape: a ``vulnerability`` block (id,
    dataSource, severity, urls[], description, cvss[], fix, advisories[] —
    the KEV catalogue link rides here as an actual advisory), a
    ``relatedVulnerabilities`` array (empty — ossuary doesn't track CVE
    aliases), a ``matchDetails`` array (the match method — ``cpe-match``
    when nmap supplied a CPE, otherwise ``exact-direct-match`` — and the
    matcher metadata Grype consumers key off for confidence weighting),
    and an ``artifact`` block (the discovered service — name, version,
    type=``binary``, locations[], cpes[], purl). EPSS rides in a
    Grype-permitted ``properties`` extension on the match so downstream
    consumers that key off the live signal find it in a predictable slot.
    """
    cve_id = finding.get("cve_id") or "UNKNOWN"
    product = service.get("product")
    version = service.get("version")
    cpe = service.get("cpe")
    severity = _grype_severity(finding.get("severity"))
    sev_score = _parse_severity(finding.get("severity"))
    ip = asset["ip"]
    port = service["port"]
    protocol = service["protocol"]
    location = f"{ip}:{port}/{protocol}"

    # vulnerability.cvss — Grype's own shape carries the numeric score
    # under metrics; we emit the numeric score when known so consumers that
    # filter on a CVSS metric still work.
    cvss: list[dict] = []
    if sev_score is not None:
        cvss.append({
            "source": "ossuary",
            "type": "Primary",
            "version": "3.1",
            "vector": "",
            "metrics": {
                "baseScore": sev_score,
                "exploitabilityScore": 0.0,
                "impactScore": 0.0,
            },
            "vendorMetadata": {},
        })

    # vulnerability.advisories — Grype's slot for vendor-extended advisory
    # links. We use it for the KEV catalogue link so a Grype consumer
    # already iterating advisories sees the confirmed-exploited signal.
    advisories: list[dict] = []
    if finding.get("kev"):
        advisories.append({
            "id": "CISA-KEV",
            "link": (
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            ),
        })

    # vulnerability.urls — Grype's own canonical-link list.
    urls = [
        f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    ]

    # matchDetails — Grype's match-method record. cpe-match is the high-
    # confidence path Grype uses when the SBOM's CPE matched the
    # vulnerability database's CPE; ossuary's nmap-supplied CPE is exactly
    # that signal, so we use cpe-match when a CPE is present and the
    # exact-direct-match fallback otherwise.
    if cpe:
        match_details = [{
            "type": "cpe-match",
            "matcher": "ossuary-cve-matcher",
            "searchedBy": {
                "namespace": "nvd:cpe",
                "cpes": [cpe],
                "package": {
                    "name": product or "",
                    "version": version or "",
                },
            },
            "found": {
                "vulnerabilityID": cve_id,
                "versionConstraint": "",
                "cpes": [cpe],
            },
            "fix": {"suggestedVersion": ""},
        }]
    else:
        match_details = [{
            "type": "exact-direct-match",
            "matcher": "ossuary-cve-matcher",
            "searchedBy": {
                "package": {
                    "name": product or "",
                    "version": version or "",
                },
            },
            "found": {
                "vulnerabilityID": cve_id,
                "versionConstraint": "",
            },
            "fix": {"suggestedVersion": ""},
        }]

    # artifact — Grype's discovered-component record. type=binary mirrors
    # the type Grype itself emits for a network-service / binary-cataloged
    # find, since ossuary doesn't scan language manifests; locations carry
    # the host:port that identifies the service.
    artifact = {
        "id": f"{ip}-{port}-{protocol}",
        "name": product or service.get("name") or f"{protocol}/{port}",
        "version": version or "",
        "type": "binary",
        "locations": [{
            "path": location,
        }],
        "language": "",
        "licenses": [],
        "cpes": [cpe] if cpe else [],
        "purl": _grype_purl(product, version) or "",
        "upstreams": [],
        "metadataType": "",
        "metadata": None,
    }

    # properties — Grype's open vendor-extension slot. EPSS rides here so
    # consumers keying off the live signal find it in a predictable place.
    # KEV is also surfaced as a top-level boolean so a consumer iterating
    # matches once can pick it up without walking advisories[].
    properties: dict = {}
    epss = finding.get("epss_score")
    if isinstance(epss, (int, float)):
        properties["ossuary.epss_score"] = epss
    if finding.get("kev"):
        properties["ossuary.kev"] = True
    source = finding.get("source")
    if source:
        properties["ossuary.source"] = source

    match = {
        "vulnerability": {
            "id": cve_id,
            "dataSource": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "namespace": "nvd:cpe",
            "severity": severity,
            "urls": urls,
            "description": finding.get("summary") or "",
            "cvss": cvss,
            "fix": {
                "versions": [],
                "state": "unknown",
            },
            "advisories": advisories,
        },
        "relatedVulnerabilities": [],
        "matchDetails": match_details,
        "artifact": artifact,
    }
    if properties:
        match["properties"] = properties
    return match


def to_grype_json(state: dict) -> str:
    """Serialise the engagement state as a Grype ``-o json`` document.

    Emits the byte-recognisable Grype JSON shape every Anchore-ecosystem
    downstream consumer reads — the Grype GitHub Action, Anchore
    Enterprise, Harbor, DefectDojo's Grype parser, dependency-track-Grype.
    The top-level wrapper carries ``matches`` (one entry per finding,
    grouped under each discovered service), ``source`` (the engagement
    DB as a Grype source), ``distro`` (empty — ossuary doesn't
    fingerprint the host OS), and ``descriptor`` (the running ossuary
    version + a configuration block).

    Like every other dump format this reads off ``build_state``, so the
    document honours ``--tag``, the actionability filters (``--kev-only``
    / ``--min-epss`` / ``--min-severity``), ``--sort-by-priority`` and
    ``--vex`` suppression identically. Like SARIF and Jira it is
    finding-centric — a service with no finding produces no entries in
    ``matches`` — and an empty engagement still yields a valid document
    with an empty ``matches`` array.
    """
    matches: list[dict] = []
    for asset in state["assets"]:
        for svc in asset["services"]:
            for f in svc["findings"]:
                matches.append(_grype_match(f, asset, svc))

    document = {
        "matches": matches,
        "source": {
            "type": "directory",
            "target": "ossuary-engagement",
        },
        "distro": {
            "name": "",
            "version": "",
            "idLike": [],
        },
        "descriptor": {
            "name": "ossuary",
            "version": __version__,
            "configuration": {
                "output": ["json"],
                "scope": "engagement",
            },
            "db": {
                "built": "",
                "schemaVersion": 0,
                "location": "",
                "checksum": "",
                "error": None,
            },
        },
    }
    return json.dumps(document, indent=2, sort_keys=False)


def dump(
    db_path: str | Path,
    fmt: str = "json",
    tag: str | None = None,
    *,
    min_epss: float | None = None,
    min_severity: float | None = None,
    kev_only: bool = False,
    since: str | None = None,
    until: str | None = None,
    sort_by_priority: bool = False,
    vex_path: str | Path | None = None,
) -> str:
    """Return the engagement state as a serialised string in the given format.

    `fmt` is one of ``json``, ``csv``, ``markdown``, ``html``, ``sarif``,
    ``jira`` (an issue-tracker import CSV for Jira / Linear), ``cyclonedx``
    (a CycloneDX 1.5 SBOM linking each finding back to its component),
    ``spdx`` (an SPDX 2.3 SBOM — the ISO/IEC 5962:2021 standard alongside
    CycloneDX — one package per service with a SECURITY external reference per
    matched CVE), or ``vex`` (a standalone OpenVEX document, one ``affected``
    statement per finding — the editable triage worksheet that is the inverse of
    the ``--vex`` suppression-import path and round-trips through it), or
    ``cdx-vex`` (a CycloneDX 1.5 VEX document — the CycloneDX-native counterpart
    to OpenVEX, with an ``analysis.state`` of ``in_triage`` on every
    vulnerability for a hunter to edit down to ``not_affected`` /
    ``false_positive`` / ``resolved``, ready to ship into a Dependency-Track /
    Anchore / CycloneDX-consuming pipeline), or ``trivy-table`` (a Trivy-style
    text-table report — one per-target section per discovered service, with
    Trivy's familiar Unicode-box-drawn table and ``Total: N (UNKNOWN: a, ...)``
    summary line, byte-recognisable in a workflow already tuned for Trivy
    output), or ``grype-json`` (the Anchore-ecosystem counterpart — Grype's
    own ``-o json`` shape: a top-level ``matches`` array carrying one
    ``vulnerability`` + ``artifact`` + ``matchDetails`` block per finding,
    byte-recognisable to every Grype consumer — the Grype GitHub Action,
    Anchore Enterprise, Harbor, DefectDojo's Grype parser — so an
    engagement's findings drop into either the Trivy or the Grype CI
    workflow without learning a new layout).
    `tag`, when set,
    restricts the export to assets carrying that tag label. `min_epss`,
    `min_severity`, and `kev_only` are actionability filters: each restricts the
    export to findings clearing that threshold, pruning services and assets left
    with no surviving findings. They compose with `tag` and with each other.
    `since` / `until` restrict the export to findings whose `matched_at` falls
    inside the (inclusive) recency window; they compose with the other filters.
    `sort_by_priority`, when set, orders each service's findings KEV-first /
    descending-EPSS / descending-severity / CVE-id (the `match-cves` triage
    order) instead of the default alphabetical-by-CVE-id ordering.
    `vex_path`, when set, is the path to an OpenVEX JSON document; findings whose
    CVE has been ruled `not_affected` / `fixed` (for their location) are
    suppressed from the export — triage-cleared findings are hidden without being
    deleted from the DB. It composes with `tag` and the other filters.
    """
    if fmt not in SUPPORTED_FORMATS:
        supported = ", ".join(SUPPORTED_FORMATS)
        raise ValueError(
            f"unsupported dump format {fmt!r} (supported: {supported})"
        )
    suppressions = vex_load(vex_path) if vex_path is not None else None
    conn = db.require_initialised(db_path)
    try:
        state = build_state(
            conn,
            tag=tag,
            min_epss=min_epss,
            min_severity=min_severity,
            kev_only=kev_only,
            since=since,
            until=until,
            sort_by_priority=sort_by_priority,
            vex=suppressions,
        )
    finally:
        conn.close()
    if fmt == "csv":
        return to_csv(state)
    if fmt == "markdown":
        return to_markdown(state)
    if fmt == "html":
        return to_html(state)
    if fmt == "sarif":
        return to_sarif(state)
    if fmt == "jira":
        return to_jira(state)
    if fmt == "cyclonedx":
        return to_cyclonedx(state)
    if fmt == "spdx":
        return to_spdx(state)
    if fmt == "vex":
        return to_vex(state)
    if fmt == "cdx-vex":
        return to_cdx_vex(state)
    if fmt == "trivy-table":
        return to_trivy_table(state)
    if fmt == "grype-json":
        return to_grype_json(state)
    return json.dumps(state, indent=2, sort_keys=False)
