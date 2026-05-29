"""Age-staleness flagging for ossuary findings (`ossuary stale`).

Where `dump --since/--until` (Rank 16) slices findings by an *absolute* scan-time
window, `stale` slices by *relative* age: it flags every finding whose
`matched_at` timestamp is older than a threshold (default 30 days) — i.e.
findings that haven't been re-confirmed by a recent scan.

Why this matters for a hunter running `cruise` / `watch` against a long-running
program: a finding's `matched_at` is refreshed each time `match-cves` re-matches
the same CVE on the same service. A finding whose `matched_at` has gone cold has
not been re-seen since that date — either the service was patched / removed (and
the stale row is now noise to clean up) or it's a long-standing exposure that has
sat unresolved for weeks. Both are signals worth surfacing: the first to prune,
the second to escalate. The age, not the absolute date, is the question, so the
threshold is expressed in days relative to "now".

A finding with no recorded `matched_at` is treated as stale once a threshold is
set — consistent with the actionability / recency filters in `dump`, which
exclude missing signal rather than silently passing it.

The age comparison is computed off the same `assets` / `services` / `findings`
data `dump` reads (via `dump.build_state`), so the flagged subset stays
consistent with every other read surface, and the same actionability filters
(`min_epss` / `min_severity` / `kev_only`) and `tag` scoping compose with the age
threshold. No network calls, no new schema, no new dependencies.

Output is either a human-readable text report (ordered oldest-first, so the
most-neglected finding leads) or a JSON object carrying the same rows.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import db, dump
from .vex import VexSuppressions
from .vex import load as vex_load

# Default age threshold, in days, beyond which a finding is flagged stale.
DEFAULT_MAX_AGE_DAYS = 30

SUPPORTED_FORMATS = ("text", "json")

# `matched_at` is stored by sqlite `datetime('now')` as `YYYY-MM-DD HH:MM:SS`
# (UTC). We parse against that primary shape and fall back to a bare date.
_MATCHED_AT_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d")


def _parse_matched_at(value: str | None) -> datetime | None:
    """Parse a finding's `matched_at` string into a UTC-aware datetime.

    Returns ``None`` for a blank / unparseable value, so callers can treat a
    finding with no recorded scan time as having unknown age. The stored shape is
    sqlite's ``datetime('now')`` (``YYYY-MM-DD HH:MM:SS``, UTC); a bare date is
    accepted as a fallback.
    """
    if not value:
        return None
    text = str(value).strip()
    for fmt in _MATCHED_AT_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _age_days(matched_at: datetime, now: datetime) -> float:
    """Return the age of a finding in (fractional) days relative to `now`."""
    return (now - matched_at).total_seconds() / 86400.0


def build_stale(
    conn: sqlite3.Connection,
    *,
    max_age_days: float = DEFAULT_MAX_AGE_DAYS,
    now: datetime | None = None,
    tag: str | None = None,
    min_epss: float | None = None,
    min_severity: float | None = None,
    kev_only: bool = False,
    vex: VexSuppressions | None = None,
) -> dict:
    """Compute the stale-findings report as a plain dict.

    A finding is *stale* when its `matched_at` is more than `max_age_days` old
    relative to `now` (defaults to the current UTC time). A finding with no
    parseable `matched_at` is treated as stale (unknown age == not recently
    confirmed), with its `age_days` reported as ``None``.

    `tag` and the actionability filters (`min_epss` / `min_severity` /
    `kev_only`) scope the candidate set exactly as they do for `dump`, reusing
    `dump.build_state`, so the flagged subset can't drift from a scoped /
    filtered dump. The age threshold then applies on top.

    `vex`, when given, is a parsed VEX suppression index (see `ossuary.vex`):
    findings whose CVE has been ruled `not_affected` / `fixed` for their location
    are dropped from the candidate set before the age check, so a triage-cleared
    finding is never flagged stale (exactly as `dump --vex` hides it). It
    composes with the tag scoping and the actionability filters.

    The returned dict carries `max_age_days`, the reference `as_of` timestamp,
    a `count`, and a `stale` list ordered oldest-first (findings with unknown age
    sort last). Each stale entry carries the locating host / port context plus the
    finding detail and computed `age_days`.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    cutoff = now - timedelta(days=max_age_days)

    state = dump.build_state(
        conn,
        tag=tag,
        min_epss=min_epss,
        min_severity=min_severity,
        kev_only=kev_only,
        vex=vex,
    )

    stale: list[dict] = []
    for asset in state["assets"]:
        for svc in asset["services"]:
            for finding in svc["findings"]:
                matched_at = finding.get("matched_at")
                parsed = _parse_matched_at(matched_at)
                if parsed is None:
                    # Unknown age — flag as stale, age unknown.
                    age = None
                elif parsed <= cutoff:
                    age = round(_age_days(parsed, now), 2)
                else:
                    # Recently confirmed — not stale.
                    continue
                stale.append(
                    {
                        "ip": asset["ip"],
                        "hostname": asset["hostname"],
                        "port": svc["port"],
                        "protocol": svc["protocol"],
                        "cve_id": finding.get("cve_id"),
                        "severity": finding.get("severity"),
                        "epss_score": finding.get("epss_score"),
                        "kev": 1 if finding.get("kev") else 0,
                        "source": finding.get("source"),
                        "matched_at": matched_at,
                        "age_days": age,
                    }
                )

    # Oldest first (largest age leads); unknown-age (None) sinks to the bottom.
    stale.sort(key=lambda f: (f["age_days"] is None, -(f["age_days"] or 0.0), f["cve_id"] or ""))

    return {
        "max_age_days": max_age_days,
        "as_of": now.strftime("%Y-%m-%d %H:%M:%S"),
        "count": len(stale),
        "stale": stale,
    }


def _fmt_epss(epss) -> str:
    return f"{epss:.2f}" if epss is not None else "—"


def _fmt_age(age) -> str:
    return f"{age:.1f}d" if age is not None else "unknown"


def _scope_suffix(
    *,
    tag: str | None,
    min_epss: float | None,
    min_severity: float | None,
    kev_only: bool,
    vex: bool = False,
) -> str:
    """Build the ``(...)`` scope suffix recording the active tag / filters."""
    parts: list[str] = []
    if tag is not None:
        parts.append(f"tag: {tag}")
    if kev_only:
        parts.append("kev-only")
    if min_epss is not None:
        parts.append(f"epss>={min_epss:g}")
    if min_severity is not None:
        parts.append(f"severity>={min_severity:g}")
    if vex:
        parts.append("vex-suppressed")
    return f" ({', '.join(parts)})" if parts else ""


def to_text(
    report: dict,
    *,
    tag: str | None = None,
    min_epss: float | None = None,
    min_severity: float | None = None,
    kev_only: bool = False,
    vex: bool = False,
) -> str:
    """Render the stale report as a human-readable text block, oldest-first."""
    suffix = _scope_suffix(
        tag=tag,
        min_epss=min_epss,
        min_severity=min_severity,
        kev_only=kev_only,
        vex=vex,
    )
    header = (
        f"stale findings{suffix} "
        f"(> {report['max_age_days']:g} days, as of {report['as_of']})"
    )
    lines = [header, f"  count: {report['count']}"]
    if not report["stale"]:
        lines.append("  none — every finding was confirmed within the window")
        return "\n".join(lines)
    for f in report["stale"]:
        loc = f"{f['ip']}:{f['protocol']}/{f['port']}"
        sev = f["severity"] or "—"
        kev = "YES" if f["kev"] else "no"
        lines.append(
            f"  {loc}  {f['cve_id']}  age: {_fmt_age(f['age_days'])}  "
            f"severity: {sev}  EPSS: {_fmt_epss(f['epss_score'])} | KEV: {kev}  "
            f"(last seen: {f['matched_at'] or 'never'})"
        )
    return "\n".join(lines)


def stale(
    db_path: str | Path,
    fmt: str = "text",
    *,
    max_age_days: float = DEFAULT_MAX_AGE_DAYS,
    tag: str | None = None,
    min_epss: float | None = None,
    min_severity: float | None = None,
    kev_only: bool = False,
    vex_path: str | Path | None = None,
) -> str:
    """Return the stale-findings report as a serialised string.

    `fmt` is ``text`` (human-readable) or ``json`` (the same rows). `max_age_days`
    sets the staleness threshold in days. `tag` and the actionability filters
    scope the candidate set exactly as they do for `dump`.
    `vex_path`, when set, is the path to an OpenVEX JSON document; findings whose
    CVE has been ruled `not_affected` / `fixed` (for their location) are dropped
    from the candidate set before the age check, so a triage-cleared finding is
    never flagged stale. It composes with `tag` and the other filters.
    """
    if fmt not in SUPPORTED_FORMATS:
        supported = ", ".join(SUPPORTED_FORMATS)
        raise ValueError(
            f"unsupported stale format {fmt!r} (supported: {supported})"
        )
    if max_age_days < 0:
        raise ValueError("--max-age-days must be non-negative")
    suppressions = vex_load(vex_path) if vex_path is not None else None
    conn = db.require_initialised(db_path)
    try:
        report = build_stale(
            conn,
            max_age_days=max_age_days,
            tag=tag,
            min_epss=min_epss,
            min_severity=min_severity,
            kev_only=kev_only,
            vex=suppressions,
        )
    finally:
        conn.close()
    if fmt == "json":
        return json.dumps(report, indent=2, sort_keys=False)
    return to_text(
        report,
        tag=tag,
        min_epss=min_epss,
        min_severity=min_severity,
        kev_only=kev_only,
        vex=suppressions is not None,
    )
