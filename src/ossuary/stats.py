"""Engagement summary roll-up for ossuary (`ossuary stats`).

Where `dump` emits the full per-finding inventory (and R6/R8/R9 let a hunter
format, filter, and order it), `stats` gives the top-of-funnel view: a single
at-a-glance triage snapshot of the whole engagement. It answers "how big is
this engagement and where's the live risk?" without scrolling a 500-row dump.

The summary is computed from the same `assets` / `services` / `findings` data
`dump` reads, so it stays consistent with every other surface. It carries no
network calls, no new schema, and no new dependencies.

`stats` accepts the same `tag` scoping `dump` does (Rank 4 tags): with a tag
set, the roll-up covers only assets carrying that label — the natural companion
to `dump --tag` so a hunter can both summarise *and* export the same in-scope /
VIP / priority subset. Tag scoping reuses `dump.build_state`, so the scoped
counts agree with a scoped dump by construction.

`stats` also accepts the same actionability filters `dump` does (Rank 8 —
`min_epss` / `min_severity` / `kev_only`): with any set, the roll-up covers only
the findings that clear every threshold, and services / assets left with no
surviving findings are pruned — the companion to `dump --kev-only --min-epss …`
so a hunter can summarise *and* export the identical actionable subset. Like the
tag scoping, the filters reuse `dump.build_state`, so the filtered counts agree
with a filtered dump by construction. With no tag and no filter, the summary is
computed straight off the tables (the historical whole-engagement path,
byte-for-byte unchanged).

Reported counts:

  * assets / services / findings totals
  * KEV findings (CISA Known Exploited Vulnerabilities — confirmed exploited)
  * EPSS exploit-probability tiers (the live signal after NIST's enrichment
    retreat): high (>= 0.5), medium (>= 0.1), low (< 0.1), and unscored
  * numeric-severity (CVSS) tiers: critical (>= 9), high (>= 7), medium (>= 4),
    low (< 4), and blank/non-numeric (un-enriched)
  * the top findings by the `match-cves` triage order (KEV-first, then EPSS,
    then severity, then CVE id)

Output is either a human-readable text report or a JSON object carrying exactly
the same numbers (for piping into other tools).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from . import db, dump

# How many leading findings the summary lists by default, in triage order.
DEFAULT_TOP = 5

SUPPORTED_FORMATS = ("text", "json")


def _parse_severity(value) -> float | None:
    """Best-effort parse of a finding's free-text severity into a float.

    Mirrors ``dump._parse_severity`` so the two surfaces classify identically:
    a blank or non-numeric severity is "unknown" and returns ``None``.
    """
    if value is None:
        return None
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _priority_key(finding: dict) -> tuple:
    """Triage sort key, highest-priority first — same ordering ``dump`` uses.

    KEV-first, then descending EPSS, then descending numeric severity, then
    CVE id ascending as a stable final tiebreaker. Missing EPSS / severity sink
    to the bottom of their tier. For use with ``sorted`` (ascending), so the
    signal fields are negated and absent values map to the lowest rank.
    """
    kev = 1 if finding.get("kev") else 0
    epss = finding.get("epss_score")
    epss = epss if epss is not None else -1.0
    sev = _parse_severity(finding.get("severity"))
    sev = sev if sev is not None else -1.0
    cve_id = finding.get("cve_id") or ""
    return (-kev, -epss, -sev, cve_id)


def _epss_tier(epss) -> str:
    """Bucket an EPSS exploit-probability into a named tier."""
    if epss is None:
        return "unscored"
    if epss >= 0.5:
        return "high"
    if epss >= 0.1:
        return "medium"
    return "low"


def _severity_tier(sev: float | None) -> str:
    """Bucket a parsed numeric CVSS severity into a named tier."""
    if sev is None:
        return "blank"
    if sev >= 9.0:
        return "critical"
    if sev >= 7.0:
        return "high"
    if sev >= 4.0:
        return "medium"
    return "low"


def _aggregate(
    asset_count: int,
    service_count: int,
    findings: list[dict],
    *,
    top: int,
) -> dict:
    """Roll counts up over a flat list of finding dicts into the summary shape.

    Shared by both the whole-engagement path and the tag-scoped path so the two
    produce the identical structure. `findings` carries at least the
    ``cve_id`` / ``summary`` / ``severity`` / ``source`` / ``epss_score`` /
    ``kev`` keys; extra keys are ignored.
    """
    kev_count = 0
    epss_tiers = {"high": 0, "medium": 0, "low": 0, "unscored": 0}
    severity_tiers = {"critical": 0, "high": 0, "medium": 0, "low": 0, "blank": 0}
    for f in findings:
        if f.get("kev"):
            kev_count += 1
        epss_tiers[_epss_tier(f.get("epss_score"))] += 1
        severity_tiers[_severity_tier(_parse_severity(f.get("severity")))] += 1

    top_findings = sorted(findings, key=_priority_key)[: max(top, 0)]

    return {
        "assets": asset_count,
        "services": service_count,
        "findings": len(findings),
        "kev": kev_count,
        "epss_tiers": epss_tiers,
        "severity_tiers": severity_tiers,
        "top_findings": [
            {
                "cve_id": f.get("cve_id"),
                "severity": f.get("severity"),
                "epss_score": f.get("epss_score"),
                "kev": 1 if f.get("kev") else 0,
                "source": f.get("source"),
            }
            for f in top_findings
        ],
    }


def _state_counts(
    conn: sqlite3.Connection,
    *,
    tag: str | None,
    min_epss: float | None,
    min_severity: float | None,
    kev_only: bool,
) -> tuple[int, int, list[dict]]:
    """Counts for the subset selected by `tag` and/or the actionability filters.

    Reuses ``dump.build_state`` with the identical scoping / filter parameters so
    the totals agree with a scoped-and-filtered ``dump`` by construction: same
    assets, same services, same surviving findings. (When the actionability
    filters are active, ``build_state`` prunes services / assets with no
    surviving findings, so those pruned rows are excluded from the counts too,
    exactly as the filtered dump excludes them.) Returns (asset_count,
    service_count, findings) where findings is a flat list of the finding dicts
    across every surviving service.
    """
    state = dump.build_state(
        conn,
        tag=tag,
        min_epss=min_epss,
        min_severity=min_severity,
        kev_only=kev_only,
    )
    assets = state["assets"]
    service_count = 0
    findings: list[dict] = []
    for asset in assets:
        service_count += len(asset["services"])
        for svc in asset["services"]:
            findings.extend(svc["findings"])
    return len(assets), service_count, findings


def build_stats(
    conn: sqlite3.Connection,
    *,
    top: int = DEFAULT_TOP,
    tag: str | None = None,
    min_epss: float | None = None,
    min_severity: float | None = None,
    kev_only: bool = False,
) -> dict:
    """Compute the engagement summary as a plain dict.

    `top` controls how many leading findings (in triage order) are returned in
    the ``top_findings`` list. The counts cover the whole scope regardless of
    `top`.

    `tag`, when set, restricts the roll-up to assets carrying that tag label —
    the same scoping `dump --tag` applies — so a hunter can summarise just their
    in-scope / VIP / priority subset.

    `min_epss`, `min_severity`, and `kev_only` are the same actionability filters
    `dump` applies (Rank 8): with any set, only findings clearing every threshold
    are counted, and services / assets left with no surviving findings are pruned
    — so the summary describes exactly the actionable subset a filtered `dump`
    would export. The tag scoping and the filters compose (a finding must clear
    both to be counted).

    When neither a tag nor any filter is set, the summary covers the whole
    engagement and is computed straight off the tables (the historical behaviour,
    byte-for-byte unchanged).
    """
    if tag is not None or min_epss is not None or min_severity is not None or kev_only:
        asset_count, service_count, findings = _state_counts(
            conn,
            tag=tag,
            min_epss=min_epss,
            min_severity=min_severity,
            kev_only=kev_only,
        )
        return _aggregate(asset_count, service_count, findings, top=top)

    asset_count = conn.execute("SELECT COUNT(*) AS c FROM assets").fetchone()["c"]
    service_count = conn.execute("SELECT COUNT(*) AS c FROM services").fetchone()["c"]
    findings = [
        dict(row)
        for row in conn.execute(
            "SELECT cve_id, summary, severity, source, epss_score, kev "
            "FROM findings"
        ).fetchall()
    ]
    return _aggregate(asset_count, service_count, findings, top=top)


def _fmt_epss(epss) -> str:
    return f"{epss:.2f}" if epss is not None else "—"


def _scope_suffix(
    *,
    tag: str | None,
    min_epss: float | None,
    min_severity: float | None,
    kev_only: bool,
) -> str:
    """Build the ``(...)`` scope suffix recording the active tag / filters.

    Returns the empty string when nothing scopes the summary, so an unscoped,
    unfiltered roll-up keeps its plain ``engagement summary`` header byte-for-byte.
    """
    parts: list[str] = []
    if tag is not None:
        parts.append(f"tag: {tag}")
    if kev_only:
        parts.append("kev-only")
    if min_epss is not None:
        parts.append(f"epss>={min_epss:g}")
    if min_severity is not None:
        parts.append(f"severity>={min_severity:g}")
    return f" ({', '.join(parts)})" if parts else ""


def to_text(
    summary: dict,
    *,
    tag: str | None = None,
    min_epss: float | None = None,
    min_severity: float | None = None,
    kev_only: bool = False,
) -> str:
    """Render the summary as a human-readable text report.

    When a tag and/or any actionability filter is given the header records the
    scope so a scoped / filtered roll-up reads unambiguously next to a
    whole-engagement one.
    """
    suffix = _scope_suffix(
        tag=tag, min_epss=min_epss, min_severity=min_severity, kev_only=kev_only
    )
    header = f"engagement summary{suffix}"
    lines = [
        header,
        f"  assets:   {summary['assets']}",
        f"  services: {summary['services']}",
        f"  findings: {summary['findings']}",
        f"  KEV (actively exploited): {summary['kev']}",
        "  EPSS tiers:",
        f"    high (>=0.50):   {summary['epss_tiers']['high']}",
        f"    medium (>=0.10): {summary['epss_tiers']['medium']}",
        f"    low (<0.10):     {summary['epss_tiers']['low']}",
        f"    unscored:        {summary['epss_tiers']['unscored']}",
        "  severity tiers:",
        f"    critical (>=9.0): {summary['severity_tiers']['critical']}",
        f"    high (>=7.0):     {summary['severity_tiers']['high']}",
        f"    medium (>=4.0):   {summary['severity_tiers']['medium']}",
        f"    low (<4.0):       {summary['severity_tiers']['low']}",
        f"    blank:            {summary['severity_tiers']['blank']}",
    ]
    top = summary["top_findings"]
    if top:
        lines.append(f"  top {len(top)} finding(s) by priority:")
        for f in top:
            sev = f["severity"] or "—"
            kev = "YES" if f["kev"] else "no"
            lines.append(
                f"    {f['cve_id']}  severity: {sev}  "
                f"EPSS: {_fmt_epss(f['epss_score'])} | KEV: {kev}"
            )
    else:
        lines.append("  top findings by priority: none")
    return "\n".join(lines)


def stats(
    db_path: str | Path,
    fmt: str = "text",
    *,
    top: int = DEFAULT_TOP,
    tag: str | None = None,
    min_epss: float | None = None,
    min_severity: float | None = None,
    kev_only: bool = False,
) -> str:
    """Return the engagement summary as a serialised string in the given format.

    `fmt` is ``text`` (human-readable) or ``json`` (the same numbers, for
    piping). `top` bounds how many leading findings appear in the priority list.
    `tag`, when set, scopes the roll-up to assets carrying that label — the same
    subset `dump --tag` exports. `min_epss`, `min_severity`, and `kev_only` are
    the same actionability filters `dump` applies (Rank 8); with any set the
    summary describes only the findings worth reporting, matching a filtered
    `dump` by construction.
    """
    if fmt not in SUPPORTED_FORMATS:
        supported = ", ".join(SUPPORTED_FORMATS)
        raise ValueError(
            f"unsupported stats format {fmt!r} (supported: {supported})"
        )
    conn = db.require_initialised(db_path)
    try:
        summary = build_stats(
            conn,
            top=top,
            tag=tag,
            min_epss=min_epss,
            min_severity=min_severity,
            kev_only=kev_only,
        )
    finally:
        conn.close()
    if fmt == "json":
        return json.dumps(summary, indent=2, sort_keys=False)
    return to_text(
        summary,
        tag=tag,
        min_epss=min_epss,
        min_severity=min_severity,
        kev_only=kev_only,
    )
