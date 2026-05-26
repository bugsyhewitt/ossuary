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

from . import db, fingerprint


def snapshot_services(conn: sqlite3.Connection) -> dict[str, dict]:
    """Capture the current service state keyed by `ip:proto/port`.

    Each value carries the fields that matter for diffing (name/product/
    version). The key set lets us detect added & removed services; the value
    comparison lets us detect changed ones (e.g. a version bump).
    """
    rows = conn.execute(
        """
        SELECT a.ip AS ip, s.port AS port, s.protocol AS protocol,
               s.name AS name, s.product AS product, s.version AS version
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
    for key in sorted(prev_keys & cur_keys):
        if previous[key] != current[key]:
            changed.append(
                {"service": key, "from": previous[key], "to": current[key]}
            )

    return {
        "added": [{"service": k, "detail": current[k]} for k in added],
        "removed": [{"service": k, "detail": previous[k]} for k in removed],
        "changed": changed,
    }


def last_snapshot(conn: sqlite3.Connection) -> dict[str, dict]:
    """Load the most recent saved cruise snapshot, or {} if none exist."""
    row = conn.execute(
        "SELECT snapshot FROM cruise_runs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return {}
    return json.loads(row["snapshot"])


def save_snapshot(conn: sqlite3.Connection, snapshot: dict[str, dict]) -> None:
    """Persist a snapshot as a new cruise_runs row."""
    conn.execute(
        "INSERT INTO cruise_runs (snapshot) VALUES (?)",
        (json.dumps(snapshot, sort_keys=True),),
    )


def cruise(db_path: str | Path) -> dict:
    """Run one cruise iteration: re-fingerprint, snapshot, diff, persist.

    Returns the diff dict. The previous snapshot is whatever was last saved in
    `cruise_runs`; if this is the first cruise, the diff treats every current
    service as `added`.
    """
    # Re-fingerprint first so the snapshot reflects the live state. The nmap
    # seam inside fingerprint is what tests mock to simulate state changes.
    fingerprint.fingerprint(db_path)

    conn = db.require_initialised(db_path)
    try:
        previous = last_snapshot(conn)
        current = snapshot_services(conn)
        result = diff_snapshots(previous, current)
        save_snapshot(conn, current)
        conn.commit()
    finally:
        conn.close()
    return result
