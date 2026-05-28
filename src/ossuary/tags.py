"""Asset tagging / label layer for ossuary.

Tags are the workflow glue for a bug bounty engagement: group hundreds of hosts
by scope (`in-scope`, `out-of-scope`), priority (`vip`, `noise`), engagement,
environment, or severity tier. Every commercial ASM platform has this; ossuary
keeps it purely additive — one table, no change to the four core tables.

The `tags` table is entity-polymorphic so the same mechanism can label assets,
services, or findings:

    tags
    ┌──────────────────────────────────────────────────────────┐
    │ id         PK                                             │
    │ entity     'asset' | 'service' | 'finding'                │
    │ entity_id  the id of the row in that entity's table       │
    │ tag        free-text label                                │
    │ tagged_at                                                 │
    │ UNIQUE(entity, entity_id, tag)                            │
    └──────────────────────────────────────────────────────────┘

v0.2 surfaces the `asset` entity through the CLI (the dominant hunter workflow);
`service` and `finding` tagging is reachable via the same table shape for future
laps without a migration.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from . import db

# The entity kinds a tag may attach to, mapped to the table whose id the
# `entity_id` column references. Used to validate input and to resolve assets.
_ENTITY_TABLES = {
    "asset": "assets",
    "service": "services",
    "finding": "findings",
}


def resolve_asset_id(conn: sqlite3.Connection, asset: str) -> int:
    """Resolve an asset selector (IP or hostname) to its assets.id.

    Hunters address assets the way they think of them — by IP, occasionally by
    hostname — not by surrogate row id. We accept either and raise a clear error
    if the host isn't in the engagement yet (discover it first).
    """
    row = conn.execute(
        "SELECT id FROM assets WHERE ip = ? OR hostname = ?",
        (asset, asset),
    ).fetchone()
    if row is None:
        raise ValueError(
            f"no asset matching {asset!r} in this engagement "
            "(run `ossuary discover` first)"
        )
    return int(row["id"])


def add_tag(db_path: str | Path, asset: str, tag: str, entity: str = "asset") -> bool:
    """Attach `tag` to the asset identified by IP/hostname.

    Returns True if a new tag row was created, False if it already existed
    (idempotent: re-tagging the same asset with the same label is a no-op, not
    an error). Raises ValueError for an unknown entity or unknown asset.
    """
    _check_entity(entity)
    tag = tag.strip()
    if not tag:
        raise ValueError("tag must be a non-empty string")
    conn = db.require_initialised(db_path)
    try:
        entity_id = _resolve_entity_id(conn, entity, asset)
        cur = conn.execute(
            "INSERT OR IGNORE INTO tags (entity, entity_id, tag) VALUES (?, ?, ?)",
            (entity, entity_id, tag),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def remove_tag(db_path: str | Path, asset: str, tag: str, entity: str = "asset") -> bool:
    """Remove `tag` from the asset. Returns True if a row was deleted."""
    _check_entity(entity)
    conn = db.require_initialised(db_path)
    try:
        entity_id = _resolve_entity_id(conn, entity, asset)
        cur = conn.execute(
            "DELETE FROM tags WHERE entity = ? AND entity_id = ? AND tag = ?",
            (entity, entity_id, tag.strip()),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def list_tags(
    db_path: str | Path,
    entity: str | None = None,
    asset: str | None = None,
) -> list[dict]:
    """List tags, optionally filtered by entity kind and/or a single asset.

    Each returned dict carries the tag plus the human-meaningful selector for
    the tagged entity (an asset's IP) so output is readable without a join the
    caller has to do. Ordered by entity, then selector, then tag.
    """
    if entity is not None:
        _check_entity(entity)

    clauses: list[str] = []
    params: list[object] = []
    if entity is not None:
        clauses.append("t.entity = ?")
        params.append(entity)

    conn = db.require_initialised(db_path)
    try:
        if asset is not None:
            # Filtering by a specific asset only makes sense for asset tags.
            entity_id = resolve_asset_id(conn, asset)
            clauses.append("t.entity = 'asset' AND t.entity_id = ?")
            params.append(entity_id)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = conn.execute(
            f"""
            SELECT t.entity AS entity, t.entity_id AS entity_id, t.tag AS tag,
                   t.tagged_at AS tagged_at, a.ip AS asset_ip
            FROM tags t
            LEFT JOIN assets a
                   ON t.entity = 'asset' AND a.id = t.entity_id
            {where}
            ORDER BY t.entity, COALESCE(a.ip, ''), t.entity_id, t.tag
            """,
            params,
        ).fetchall()
    finally:
        conn.close()

    return [
        {
            "entity": r["entity"],
            "entity_id": r["entity_id"],
            "asset_ip": r["asset_ip"],
            "tag": r["tag"],
            "tagged_at": r["tagged_at"],
        }
        for r in rows
    ]


def asset_tags(conn: sqlite3.Connection, asset_id: int) -> list[str]:
    """Return the sorted list of tag labels attached to one asset.

    Helper used by `dump` and `cruise` to fold tags into their output without
    duplicating the query shape.
    """
    rows = conn.execute(
        "SELECT tag FROM tags WHERE entity = 'asset' AND entity_id = ? ORDER BY tag",
        (asset_id,),
    ).fetchall()
    return [r["tag"] for r in rows]


def asset_tag_map(conn: sqlite3.Connection) -> dict[str, list[str]]:
    """Map every tagged asset's IP to its sorted tag list.

    Used by `cruise` to snapshot tag state for diffing. Assets with no tags are
    omitted; an empty map means "no tags anywhere".
    """
    rows = conn.execute(
        """
        SELECT a.ip AS ip, t.tag AS tag
        FROM tags t
        JOIN assets a ON a.id = t.entity_id
        WHERE t.entity = 'asset'
        ORDER BY a.ip, t.tag
        """
    ).fetchall()
    out: dict[str, list[str]] = {}
    for r in rows:
        out.setdefault(r["ip"], []).append(r["tag"])
    return out


def _check_entity(entity: str) -> None:
    if entity not in _ENTITY_TABLES:
        valid = ", ".join(sorted(_ENTITY_TABLES))
        raise ValueError(f"unknown entity {entity!r} (valid: {valid})")


def _resolve_entity_id(conn: sqlite3.Connection, entity: str, selector: str) -> int:
    """Resolve a selector to the row id for the given entity kind.

    Only `asset` accepts a human IP/hostname selector; `service` and `finding`
    take a numeric row id (their natural selectors are composite and CLI-hostile
    in v0.2, so the id is the honest interface for them).
    """
    if entity == "asset":
        return resolve_asset_id(conn, selector)
    try:
        entity_id = int(selector)
    except (TypeError, ValueError):
        raise ValueError(
            f"{entity} tags require a numeric {entity} id, got {selector!r}"
        )
    table = _ENTITY_TABLES[entity]
    row = conn.execute(f"SELECT id FROM {table} WHERE id = ?", (entity_id,)).fetchone()
    if row is None:
        raise ValueError(f"no {entity} with id {entity_id} in this engagement")
    return entity_id
