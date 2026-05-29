"""Severity-context enrichment for ossuary findings: EPSS + CISA KEV + Exploit-DB.

OSV/NVD severity alone is increasingly hollow — since NIST's 2024-onward
enrichment retreat, the large majority of new CVEs ship with no analysed CVSS
at all, so ossuary's `severity` column is blank or stale for most fresh CVEs.
This module restores actionable signal by annotating each finding with:

    epss_score  — FIRST's Exploit Prediction Scoring System probability [0, 1]
                  ("how likely is this to be exploited in the next 30 days")
    kev         — 1 if CISA lists the CVE in its Known Exploited Vulnerabilities
                  catalog (i.e. confirmed exploited in the wild), else 0
    exploit     — 1 if a public exploit / PoC for the CVE is catalogued in
                  Exploit-DB (a weaponisable exploit exists and is downloadable),
                  else 0

EPSS, KEV and Exploit-DB are three *distinct* prioritisation axes. KEV answers
"is this being exploited in the wild right now?"; EPSS answers "how likely is it
to be exploited soon?"; Exploit-DB answers "does a ready-to-run public exploit
already exist?" A CVE can carry any combination — a brand-new CVE with a
published Metasploit module but no KEV listing and a low EPSS is exactly the
kind of finding a hunter wants surfaced, and only the Exploit-DB signal catches
it.

Three network seams, all mocked in tests:

    query_epss(cve_id)        -> the EPSS float, or None
    fetch_kev_catalog()       -> the raw CISA KEV catalog dict
    fetch_exploitdb_index()   -> the raw Exploit-DB files_exploits index rows

The KEV catalog and the Exploit-DB index are each a single file listing every
relevant CVE, so we download each once and cache its extracted id set in the
engagement DB (`kev_cache` / `exploitdb_cache` tables) with a 24h TTL rather
than re-fetching per CVE.
"""

from __future__ import annotations

import json
import re
import sqlite3

import httpx

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
# Exploit-DB publishes its catalogue as a CSV index (files_exploits.csv) in the
# official mirror repo. Each row's `codes` column lists the CVE ids the exploit
# targets (semicolon-separated), so the index is a complete CVE -> public-exploit
# map without scraping individual exploit pages.
EXPLOITDB_INDEX_URL = (
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
)

# How long a cached KEV catalog stays fresh before we re-download it.
KEV_TTL_HOURS = 24
# How long a cached Exploit-DB CVE-id set stays fresh before re-download.
EXPLOITDB_TTL_HOURS = 24

# Matches CVE ids embedded in an Exploit-DB `codes` cell (e.g.
# "CVE-2021-44228;OSVDB-12345"). Case-insensitive; the year/sequence shape is
# the canonical NVD form.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def query_epss(cve_id: str) -> float | None:
    """Query FIRST's EPSS API for a single CVE's exploit probability.

    Returns the EPSS score as a float in [0, 1], or None when EPSS has no score
    for the CVE (e.g. brand-new or rejected ids). Network seam — mocked in
    tests.
    """
    resp = httpx.get(EPSS_URL, params={"cve": cve_id}, timeout=30.0)
    resp.raise_for_status()
    data = resp.json().get("data") or []
    if not data:
        return None
    raw = data[0].get("epss")
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def fetch_kev_catalog() -> dict:
    """Download the full CISA Known Exploited Vulnerabilities catalog.

    Returns the parsed JSON dict (whose `vulnerabilities` array holds one entry
    per KEV CVE). Network seam — mocked in tests.
    """
    resp = httpx.get(KEV_URL, timeout=60.0)
    resp.raise_for_status()
    return resp.json()


def kev_ids_from_catalog(catalog: dict) -> set[str]:
    """Extract the set of CVE ids from a raw KEV catalog dict."""
    return {
        v["cveID"]
        for v in catalog.get("vulnerabilities", []) or []
        if v.get("cveID")
    }


def get_kev_ids(conn: sqlite3.Connection) -> set[str]:
    """Return the set of KEV CVE ids, using the DB cache when it is fresh.

    On a cache miss or stale entry (older than KEV_TTL_HOURS), downloads the
    catalog via `fetch_kev_catalog`, stores the extracted id set in `kev_cache`,
    and returns it. Otherwise serves the cached ids with no network call.
    """
    row = conn.execute(
        "SELECT ids FROM kev_cache "
        "WHERE fetched_at > datetime('now', ?) "
        "ORDER BY id DESC LIMIT 1",
        (f"-{KEV_TTL_HOURS} hours",),
    ).fetchone()
    if row is not None:
        return set(json.loads(row["ids"]))

    catalog = fetch_kev_catalog()
    ids = kev_ids_from_catalog(catalog)
    # Single-row cache: clear old entries, then insert the fresh snapshot.
    conn.execute("DELETE FROM kev_cache")
    conn.execute(
        "INSERT INTO kev_cache (ids) VALUES (?)",
        (json.dumps(sorted(ids)),),
    )
    conn.commit()
    return ids


def fetch_exploitdb_index() -> str:
    """Download Exploit-DB's files_exploits.csv index.

    Returns the raw CSV text (one row per catalogued exploit; the ``codes``
    column lists the CVE ids the exploit targets). Network seam — mocked in
    tests.
    """
    resp = httpx.get(EXPLOITDB_INDEX_URL, timeout=60.0)
    resp.raise_for_status()
    return resp.text


def exploit_ids_from_index(index_text: str) -> set[str]:
    """Extract the set of CVE ids referenced by any exploit in the EDB index.

    Rather than CSV-parse the (occasionally messy) index, we scan the whole text
    for canonical CVE id tokens — every CVE that appears anywhere in the index is
    one that has at least one public exploit catalogued. Ids are upper-cased so
    membership tests are case-insensitive.
    """
    return {m.group(0).upper() for m in _CVE_RE.finditer(index_text or "")}


def get_exploit_ids(conn: sqlite3.Connection) -> set[str]:
    """Return the set of CVE ids with a public Exploit-DB exploit, DB-cached.

    Mirrors :func:`get_kev_ids`: on a cache miss or an entry older than
    EXPLOITDB_TTL_HOURS, downloads the index via :func:`fetch_exploitdb_index`,
    stores the extracted id set in `exploitdb_cache`, and returns it. Otherwise
    serves the cached ids with no network call.
    """
    row = conn.execute(
        "SELECT ids FROM exploitdb_cache "
        "WHERE fetched_at > datetime('now', ?) "
        "ORDER BY id DESC LIMIT 1",
        (f"-{EXPLOITDB_TTL_HOURS} hours",),
    ).fetchone()
    if row is not None:
        return set(json.loads(row["ids"]))

    index_text = fetch_exploitdb_index()
    ids = exploit_ids_from_index(index_text)
    # Single-row cache: clear old entries, then insert the fresh snapshot.
    conn.execute("DELETE FROM exploitdb_cache")
    conn.execute(
        "INSERT INTO exploitdb_cache (ids) VALUES (?)",
        (json.dumps(sorted(ids)),),
    )
    conn.commit()
    return ids


def enrich_finding(
    conn: sqlite3.Connection,
    cve_id: str,
    kev_ids: set[str],
    exploit_ids: set[str] | None = None,
) -> dict:
    """Compute enrichment for one CVE: EPSS score, KEV and public-exploit status.

    `kev_ids` and `exploit_ids` are passed in (each fetched once per run via
    get_kev_ids / get_exploit_ids) so we don't re-resolve the catalogues for
    every finding. Only EPSS is a per-CVE call. `exploit_ids` defaults to an
    empty set so callers that haven't resolved the Exploit-DB index simply get
    ``exploit=0`` (the historical, pre-Exploit-DB behaviour). Comparison is
    case-insensitive on the canonical CVE id form.
    Returns {"epss_score": float|None, "kev": 0|1, "exploit": 0|1}.
    """
    score = query_epss(cve_id)
    cve_upper = cve_id.upper()
    has_exploit = exploit_ids is not None and cve_upper in exploit_ids
    return {
        "epss_score": score,
        "kev": 1 if cve_id in kev_ids else 0,
        "exploit": 1 if has_exploit else 0,
    }
