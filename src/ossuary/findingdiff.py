"""Finding-level diff between two engagement snapshots (`ossuary diff`).

`cruise` (and the `watch` daemon that loops it) diffs the *service* surface of a
single engagement DB over time — ports opening, version bumps, services
disappearing. What it never answers is the question a hunter asks after a
re-scan: **which CVE findings are new, and which got resolved (patched)?** The
cruise snapshot doesn't even carry findings, so there is no way to see that
`CVE-2024-1234` vanished off a host (the admin patched) or that a fresh
`CVE-2025-9999` just appeared on a newly-exposed version.

`ossuary diff` closes that gap. It compares the findings of two engagement DB
files — a baseline (the earlier scan) and a current one (the later scan) — and
classifies every distinct finding as:

    new        present in current, absent in baseline  (newly exposed)
    resolved   present in baseline, absent in current  (patched / removed)
    persisting present in both                          (still exposed)

A finding's identity is the triple ``(ip, protocol/port, cve_id)`` — the same
host:service location the SARIF / HTML exports use — so the same CVE on two
different hosts is two findings, and a CVE that moves ports counts as one
resolved + one new (it genuinely moved).

This is the natural triage companion to a re-scan: run a fresh engagement into a
new DB (or keep a dated copy of the baseline), then ``ossuary diff`` to see
exactly what changed in the *vulnerability* surface, not just the service one.

Both DBs are read through ``dump.build_state``, so the diff honours the same
``--tag`` scoping and actionability filters (``min_epss`` / ``min_severity`` /
``kev_only``) the rest of the suite applies — letting a hunter scope the diff to
"only the new *actionable* findings on my in-scope hosts." ``--tag`` scopes each
side to assets carrying that label *in that DB*, mirroring how ``dump --tag`` /
``stats --tag`` / ``stale --tag`` scope a single DB. The current DB's finding
detail (severity / EPSS / KEV /
summary) is reported for ``new`` and ``persisting`` entries; the baseline's is
reported for ``resolved`` ones (the current DB no longer has them). Pure Python,
no new schema, no new dependency, no network.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import db, dump

SUPPORTED_FORMATS = ("text", "json")


def _location(ip: str, protocol: str, port) -> str:
    """Render a finding's host:service location key (``ip:proto/port``)."""
    return f"{ip}:{protocol}/{port}"


def _index_findings(state: dict) -> dict[tuple[str, str], dict]:
    """Flatten a ``build_state`` result to a map keyed by (location, cve_id).

    Each value carries the finding detail plus its resolved location string and
    the owning service's product/version, so a diff entry can be reported with
    full host:service context regardless of which side it came from. When the
    same (location, cve_id) appears twice (it shouldn't — the findings table is
    unique on (service_id, cve_id) — but a malformed DB could), last write wins.
    """
    index: dict[tuple[str, str], dict] = {}
    for asset in state["assets"]:
        ip = asset["ip"]
        for svc in asset["services"]:
            location = _location(ip, svc["protocol"], svc["port"])
            for f in svc["findings"]:
                cve_id = f.get("cve_id")
                if not cve_id:
                    continue
                index[(location, cve_id)] = {
                    "location": location,
                    "ip": ip,
                    "port": svc["port"],
                    "protocol": svc["protocol"],
                    "product": svc.get("product"),
                    "version": svc.get("version"),
                    "cve_id": cve_id,
                    "summary": f.get("summary"),
                    "severity": f.get("severity"),
                    "source": f.get("source"),
                    "epss_score": f.get("epss_score"),
                    "kev": 1 if f.get("kev") else 0,
                }
    return index


def _entry(detail: dict) -> dict:
    """Project an indexed finding into a stable diff-entry shape."""
    return {
        "location": detail["location"],
        "ip": detail["ip"],
        "port": detail["port"],
        "protocol": detail["protocol"],
        "product": detail["product"],
        "version": detail["version"],
        "cve_id": detail["cve_id"],
        "summary": detail["summary"],
        "severity": detail["severity"],
        "source": detail["source"],
        "epss_score": detail["epss_score"],
        "kev": detail["kev"],
    }


def _sort_entries(entries: list[dict]) -> list[dict]:
    """Order diff entries deterministically by location then CVE id."""
    return sorted(entries, key=lambda e: (e["location"], e["cve_id"] or ""))


def diff_states(baseline: dict, current: dict) -> dict:
    """Diff two ``build_state`` results into new / resolved / persisting findings.

    A finding is keyed on (``ip:proto/port``, ``cve_id``). The result classifies
    every distinct key: in ``current`` only -> ``new``; in ``baseline`` only ->
    ``resolved``; in both -> ``persisting``. ``new`` / ``persisting`` entries
    carry the *current* DB's detail; ``resolved`` entries carry the *baseline*'s
    (the current DB no longer holds them). Each list is sorted by location then
    CVE id.
    """
    base_idx = _index_findings(baseline)
    cur_idx = _index_findings(current)

    base_keys = set(base_idx)
    cur_keys = set(cur_idx)

    new = [_entry(cur_idx[k]) for k in cur_keys - base_keys]
    resolved = [_entry(base_idx[k]) for k in base_keys - cur_keys]
    persisting = [_entry(cur_idx[k]) for k in cur_keys & base_keys]

    return {
        "new": _sort_entries(new),
        "resolved": _sort_entries(resolved),
        "persisting": _sort_entries(persisting),
    }


def _read_state(
    db_path: str | Path,
    *,
    tag: str | None,
    min_epss: float | None,
    min_severity: float | None,
    kev_only: bool,
) -> dict:
    """Open an engagement DB and return its scoped / filtered ``build_state``.

    ``tag`` scopes the side to assets carrying that label in *this* DB; the
    actionability filters are applied on top. So a diff scoped with either
    compares only the findings that survive the scope on *each* side — i.e.
    "what's new among the in-scope / actionable findings." With neither this is
    the full finding inventory of the DB.
    """
    conn = db.require_initialised(db_path)
    try:
        return dump.build_state(
            conn,
            tag=tag,
            min_epss=min_epss,
            min_severity=min_severity,
            kev_only=kev_only,
        )
    finally:
        conn.close()


def build_diff(
    baseline_db: str | Path,
    current_db: str | Path,
    *,
    tag: str | None = None,
    min_epss: float | None = None,
    min_severity: float | None = None,
    kev_only: bool = False,
) -> dict:
    """Compute the finding-level diff between two engagement DB files.

    ``baseline_db`` is the earlier scan, ``current_db`` the later one. Returns
    the ``diff_states`` dict (``new`` / ``resolved`` / ``persisting``). ``tag``
    scopes each side to assets carrying that label *in that DB*, and the
    actionability filters (``min_epss`` / ``min_severity`` / ``kev_only``) are
    applied identically to both sides before diffing — so the diff describes the
    change within the scoped (in-scope / actionable) subset. ``tag`` composes
    with the actionability filters.
    """
    baseline = _read_state(
        baseline_db,
        tag=tag,
        min_epss=min_epss,
        min_severity=min_severity,
        kev_only=kev_only,
    )
    current = _read_state(
        current_db,
        tag=tag,
        min_epss=min_epss,
        min_severity=min_severity,
        kev_only=kev_only,
    )
    return diff_states(baseline, current)


def _fmt_epss(epss) -> str:
    return f"{epss:.2f}" if isinstance(epss, (int, float)) else "—"


def _fmt_entry(entry: dict) -> str:
    """Render one diff entry as a compact human line."""
    sev = entry["severity"] or "—"
    kev = "YES" if entry["kev"] else "no"
    detail_bits = [p for p in (entry.get("product"), entry.get("version")) if p]
    detail = f" ({' '.join(detail_bits)})" if detail_bits else ""
    return (
        f"    {entry['location']}{detail}  {entry['cve_id']}  "
        f"severity: {sev}  EPSS: {_fmt_epss(entry['epss_score'])} | KEV: {kev}"
    )


def to_text(diff: dict) -> str:
    """Render a finding diff as a human-readable report.

    Leads with a one-line count header (new / resolved / persisting), then lists
    the new and resolved findings — the two that demand attention. Persisting
    findings are counted but not individually listed (they're unchanged exposure;
    a plain ``dump`` covers them) so the report stays focused on what moved.
    """
    new = diff["new"]
    resolved = diff["resolved"]
    persisting = diff["persisting"]
    lines = [
        f"finding diff: {len(new)} new, {len(resolved)} resolved, "
        f"{len(persisting)} persisting"
    ]
    if new:
        lines.append(f"  new ({len(new)}) — newly exposed:")
        lines.extend(_fmt_entry(e) for e in new)
    if resolved:
        lines.append(f"  resolved ({len(resolved)}) — patched / removed:")
        lines.extend(_fmt_entry(e) for e in resolved)
    if not new and not resolved:
        lines.append("  (no findings appeared or were resolved)")
    return "\n".join(lines)


def diff(
    baseline_db: str | Path,
    current_db: str | Path,
    fmt: str = "text",
    *,
    tag: str | None = None,
    min_epss: float | None = None,
    min_severity: float | None = None,
    kev_only: bool = False,
) -> str:
    """Return the finding diff between two DBs as a serialised string.

    ``fmt`` is ``text`` (human-readable) or ``json`` (the same structure, for
    piping). ``tag`` scopes each side to assets carrying that label, and the
    actionability filters scope both sides before diffing. See
    :func:`build_diff` for the comparison semantics.
    """
    if fmt not in SUPPORTED_FORMATS:
        supported = ", ".join(SUPPORTED_FORMATS)
        raise ValueError(f"unsupported diff format {fmt!r} (supported: {supported})")
    result = build_diff(
        baseline_db,
        current_db,
        tag=tag,
        min_epss=min_epss,
        min_severity=min_severity,
        kev_only=kev_only,
    )
    if fmt == "json":
        return json.dumps(result, indent=2, sort_keys=False)
    return to_text(result)
