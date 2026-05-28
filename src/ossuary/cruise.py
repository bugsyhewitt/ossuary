"""Cruise mode for ossuary — single-invocation re-scan + diff.

A "cruise" re-fingerprints the engagement's known assets, snapshots the current
service state into the `cruise_runs` table, diffs that snapshot against the
previous run, and reports added / removed / changed services.

v0.1 is a single-invocation diff: run once, diff against last saved state,
print, exit. No scheduler, no daemon (both explicitly NOT-in-v0.1).
`apscheduler` and long-running modes are deferred to post-v0.1.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from . import db, fingerprint, tags
from .profiles import DEFAULT_PROFILE


def snapshot_services(conn: sqlite3.Connection) -> dict[str, dict]:
    """Capture the current service state keyed by `ip:proto/port`.

    Each value carries the fields that matter for diffing (name/product/
    version). The key set lets us detect added & removed services; the value
    comparison lets us detect changed ones (e.g. a version bump).
    """
    rows = conn.execute(
        """
        SELECT a.ip AS ip, s.port AS port, s.protocol AS protocol,
               s.name AS name, s.product AS product, s.version AS version,
               s.scan_profile AS scan_profile
        FROM services s
        JOIN assets a ON a.id = s.asset_id
        ORDER BY a.ip, s.port
        """
    ).fetchall()
    snapshot: dict[str, dict] = {}
    for r in rows:
        key = f"{r['ip']}:{r['protocol']}/{r['port']}"
        snapshot[key] = {
            "name": r["name"],
            "product": r["product"],
            "version": r["version"],
            "scan_profile": r["scan_profile"],
        }
    return snapshot


def diff_snapshots(previous: dict[str, dict], current: dict[str, dict]) -> dict:
    """Diff two service snapshots.

    Returns {"added": [...], "removed": [...], "changed": [...]} where each
    entry identifies the service by key. `changed` entries include the before
    and after field values.
    """
    prev_keys = set(previous)
    cur_keys = set(current)

    added = sorted(cur_keys - prev_keys)
    removed = sorted(prev_keys - cur_keys)

    changed: list[dict] = []
    profile_changes: list[dict] = []
    for key in sorted(prev_keys & cur_keys):
        if previous[key] != current[key]:
            changed.append(
                {"service": key, "from": previous[key], "to": current[key]}
            )
        # Independently flag a scan-profile mismatch — a service re-scanned under
        # a different named profile than last time. Older snapshots predate the
        # column; treat a missing profile as the implicit "default".
        prev_profile = previous[key].get("scan_profile", DEFAULT_PROFILE)
        cur_profile = current[key].get("scan_profile", DEFAULT_PROFILE)
        if prev_profile != cur_profile:
            profile_changes.append(
                {"service": key, "from": prev_profile, "to": cur_profile}
            )

    return {
        "added": [{"service": k, "detail": current[k]} for k in added],
        "removed": [{"service": k, "detail": previous[k]} for k in removed],
        "changed": changed,
        "profile_changes": profile_changes,
    }


def diff_tags(
    previous: dict[str, list[str]], current: dict[str, list[str]]
) -> list[dict]:
    """Diff two per-asset tag snapshots.

    Each input maps an asset IP to its sorted tag list. Returns one entry per
    asset whose tag set changed, naming the tags added and removed since the
    previous cruise. Assets with no change are omitted. Ordered by asset IP.
    """
    changes: list[dict] = []
    for ip in sorted(set(previous) | set(current)):
        before = set(previous.get(ip, []))
        after = set(current.get(ip, []))
        if before == after:
            continue
        changes.append(
            {
                "asset": ip,
                "added": sorted(after - before),
                "removed": sorted(before - after),
            }
        )
    return changes


def last_snapshot(conn: sqlite3.Connection) -> dict[str, dict]:
    """Load the most recent saved cruise service snapshot, or {} if none exist."""
    row = conn.execute(
        "SELECT snapshot FROM cruise_runs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return {}
    return json.loads(row["snapshot"])


def last_tag_snapshot(conn: sqlite3.Connection) -> dict[str, list[str]]:
    """Load the most recent saved tag snapshot, or {} if none exist.

    Older cruise_runs rows predate the `tag_snapshot` column (migrated in) and
    carry NULL there — treated as "no tags then" so the first post-upgrade
    cruise reports current tags as additions rather than crashing.
    """
    row = conn.execute(
        "SELECT tag_snapshot FROM cruise_runs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if row is None or row["tag_snapshot"] is None:
        return {}
    return json.loads(row["tag_snapshot"])


def save_snapshot(
    conn: sqlite3.Connection,
    snapshot: dict[str, dict],
    tag_snapshot: dict[str, list[str]],
) -> None:
    """Persist a service + tag snapshot as a new cruise_runs row."""
    conn.execute(
        "INSERT INTO cruise_runs (snapshot, tag_snapshot) VALUES (?, ?)",
        (
            json.dumps(snapshot, sort_keys=True),
            json.dumps(tag_snapshot, sort_keys=True),
        ),
    )


def cruise(db_path: str | Path, profile: str = DEFAULT_PROFILE) -> dict:
    """Run one cruise iteration: re-fingerprint, snapshot, diff, persist.

    `profile` selects the named scan profile used for the re-fingerprint; when
    it differs from the profile that produced the prior services, the resulting
    diff's `profile_changes` section flags the affected services.

    Returns the diff dict. The previous snapshot is whatever was last saved in
    `cruise_runs`; if this is the first cruise, the diff treats every current
    service as `added`.
    """
    # Re-fingerprint first so the snapshot reflects the live state. The nmap
    # seam inside fingerprint is what tests mock to simulate state changes.
    fingerprint.fingerprint(db_path, profile=profile)

    conn = db.require_initialised(db_path)
    try:
        previous = last_snapshot(conn)
        current = snapshot_services(conn)
        result = diff_snapshots(previous, current)

        prev_tags = last_tag_snapshot(conn)
        cur_tags = tags.asset_tag_map(conn)
        result["tag_changes"] = diff_tags(prev_tags, cur_tags)

        save_snapshot(conn, current, cur_tags)
        conn.commit()
    finally:
        conn.close()
    return result
