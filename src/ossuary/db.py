"""SQLite persistence layer for ossuary.

One engagement == one SQLite file. Self-contained, portable, single-file.
No MongoDB, no Postgres — stdlib sqlite3 only (v0.1 constraint).

Schema (four core tables + one enrichment cache):

    assets        — discovered hosts (one row per host)
    services      — fingerprinted services (one row per host:port)
    findings      — CVE matches against discovered service versions
    cruise_runs   — snapshots of service state per cruise invocation, for diffing
    kev_cache     — cached CISA KEV catalog ids (TTL'd, for severity enrichment)
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
    epss_score  REAL,
    kev         INTEGER NOT NULL DEFAULT 0,
    matched_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(service_id, cve_id)
);

CREATE TABLE IF NOT EXISTS cruise_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ran_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    snapshot    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS kev_cache (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ids         TEXT    NOT NULL,
    fetched_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS web_probes (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id          INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port              INTEGER NOT NULL,
    protocol          TEXT    NOT NULL DEFAULT 'https',
    status_code       INTEGER,
    server            TEXT,
    title             TEXT,
    redirect_chain    TEXT,
    tech_fingerprints TEXT,
    probed_at         TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(asset_id, port, protocol)
);
"""

# Columns added to `findings` after v0.1 for severity-context enrichment. Each
# is (name, full ALTER ... ADD COLUMN clause). Applied idempotently at init_db
# time so engagement DBs created before enrichment landed gain them on next run
# without losing their existing rows.
_FINDINGS_MIGRATIONS = (
    ("epss_score", "ALTER TABLE findings ADD COLUMN epss_score REAL"),
    ("kev", "ALTER TABLE findings ADD COLUMN kev INTEGER NOT NULL DEFAULT 0"),
)


def _column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    """Return the set of column names on a table."""
    return {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}


def _migrate(conn: sqlite3.Connection) -> None:
    """Apply additive schema migrations idempotently.

    CREATE TABLE IF NOT EXISTS only creates missing tables — it does not add
    columns to a table that already exists with an older shape. So for DBs that
    predate the enrichment columns we ALTER them in, guarded by a column check.
    """
    if "findings" not in table_names(conn):
        return
    existing = _column_names(conn, "findings")
    for name, ddl in _FINDINGS_MIGRATIONS:
        if name not in existing:
            conn.execute(ddl)
    conn.commit()


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
    _migrate(conn)
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
    epss_score: float | None = None,
    kev: int = 0,
) -> int:
    """Insert or update a finding by (service_id, cve_id).

    `epss_score` (FIRST exploit-probability float) and `kev` (1 if the CVE is in
    CISA's Known Exploited Vulnerabilities catalog) are enrichment fields; they
    default to None/0 so callers that don't enrich behave exactly as before.
    """
    conn.execute(
        """
        INSERT INTO findings (service_id, cve_id, summary, severity, source,
                              epss_score, kev)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(service_id, cve_id) DO UPDATE SET
            summary    = excluded.summary,
            severity   = excluded.severity,
            source     = excluded.source,
            epss_score = excluded.epss_score,
            kev        = excluded.kev
        """,
        (service_id, cve_id, summary, severity, source, epss_score, kev),
    )
    row = conn.execute(
        "SELECT id FROM findings WHERE service_id = ? AND cve_id = ?",
        (service_id, cve_id),
    ).fetchone()
    return int(row["id"])
