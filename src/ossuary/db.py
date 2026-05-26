"""SQLite persistence layer for ossuary.

One engagement == one SQLite file. Self-contained, portable, single-file.
No MongoDB, no Postgres — stdlib sqlite3 only (v0.1 constraint).

Schema (four tables):

    assets        — discovered hosts (one row per host)
    services      — fingerprinted services (one row per host:port)
    findings      — CVE matches against discovered service versions
    cruise_runs   — snapshots of service state per cruise invocation, for diffing
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

# The four core tables required by the v0.1 criteria.
EXPECTED_TABLES = ("assets", "services", "findings", "cruise_runs")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT    NOT NULL UNIQUE,
    hostname    TEXT,
    state       TEXT    NOT NULL DEFAULT 'up',
    discovered_at TEXT  NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS services (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT    NOT NULL DEFAULT 'tcp',
    name        TEXT,
    product     TEXT,
    version     TEXT,
    cpe         TEXT,
    fingerprinted_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(asset_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id  INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    cve_id      TEXT    NOT NULL,
    summary     TEXT,
    severity    TEXT,
    source      TEXT    NOT NULL DEFAULT 'osv.dev',
    matched_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(service_id, cve_id)
);

CREATE TABLE IF NOT EXISTS cruise_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ran_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    snapshot    TEXT    NOT NULL
);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open (and configure) a connection to an engagement DB file.

    Enables foreign keys and row-as-dict access. Does NOT create the schema —
    call init_db for that, so that `discover` against a non-initialised DB
    fails loudly rather than silently creating a half-formed file.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str | Path) -> sqlite3.Connection:
    """Create the engagement DB file and all four tables. Idempotent."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def table_names(conn: sqlite3.Connection) -> set[str]:
    """Return the set of user table names present in the connection."""
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
    ).fetchall()
    return {r["name"] for r in rows}


def is_initialised(db_path: str | Path) -> bool:
    """True if the DB file exists and contains all expected tables."""
    if not Path(db_path).exists():
        return False
    conn = connect(db_path)
    try:
        return set(EXPECTED_TABLES).issubset(table_names(conn))
    finally:
        conn.close()


def require_initialised(db_path: str | Path) -> sqlite3.Connection:
    """Open a DB that must already be initialised, else raise.

    Used by every subcommand except `init` so operators get a clear error
    instead of a confusing empty result against a missing/empty file.
    """
    if not is_initialised(db_path):
        raise RuntimeError(
            f"database {db_path!r} is not initialised — run `ossuary init --db {db_path}` first"
        )
    return connect(db_path)


def upsert_asset(conn: sqlite3.Connection, ip: str, hostname: str | None, state: str) -> int:
    """Insert or update an asset by IP, returning its row id."""
    conn.execute(
        """
        INSERT INTO assets (ip, hostname, state) VALUES (?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            hostname = excluded.hostname,
            state    = excluded.state
        """,
        (ip, hostname, state),
    )
    row = conn.execute("SELECT id FROM assets WHERE ip = ?", (ip,)).fetchone()
    return int(row["id"])


def upsert_service(
    conn: sqlite3.Connection,
    asset_id: int,
    port: int,
    protocol: str,
    name: str | None,
    product: str | None,
    version: str | None,
    cpe: str | None,
) -> int:
    """Insert or update a service by (asset_id, port, protocol)."""
    conn.execute(
        """
        INSERT INTO services (asset_id, port, protocol, name, product, version, cpe)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(asset_id, port, protocol) DO UPDATE SET
            name    = excluded.name,
            product = excluded.product,
            version = excluded.version,
            cpe     = excluded.cpe,
            fingerprinted_at = datetime('now')
        """,
        (asset_id, port, protocol, name, product, version, cpe),
    )
    row = conn.execute(
        "SELECT id FROM services WHERE asset_id = ? AND port = ? AND protocol = ?",
        (asset_id, port, protocol),
    ).fetchone()
    return int(row["id"])


def upsert_finding(
    conn: sqlite3.Connection,
    service_id: int,
    cve_id: str,
    summary: str | None,
    severity: str | None,
    source: str = "osv.dev",
) -> int:
    """Insert or update a finding by (service_id, cve_id)."""
    conn.execute(
        """
        INSERT INTO findings (service_id, cve_id, summary, severity, source)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(service_id, cve_id) DO UPDATE SET
            summary  = excluded.summary,
            severity = excluded.severity,
            source   = excluded.source
        """,
        (service_id, cve_id, summary, severity, source),
    )
    row = conn.execute(
        "SELECT id FROM findings WHERE service_id = ? AND cve_id = ?",
        (service_id, cve_id),
    ).fetchone()
    return int(row["id"])
