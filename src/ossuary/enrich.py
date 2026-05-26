"""Severity-context enrichment for ossuary findings: EPSS + CISA KEV.

OSV/NVD severity alone is increasingly hollow — since NIST's 2024-onward
enrichment retreat, the large majority of new CVEs ship with no analysed CVSS
at all, so ossuary's `severity` column is blank or stale for most fresh CVEs.
This module restores actionable signal by annotating each finding with:

    epss_score  — FIRST's Exploit Prediction Scoring System probability [0, 1]
                  ("how likely is this to be exploited in the next 30 days")
    kev         — 1 if CISA lists the CVE in its Known Exploited Vulnerabilities
                  catalog (i.e. confirmed exploited in the wild), else 0

Two network seams, both mocked in tests:

    query_epss(cve_id)   -> the EPSS float, or None
    fetch_kev_catalog()  -> the raw CISA KEV catalog dict

The KEV catalog is a single ~1MB file listing every KEV CVE, so we download it
once and cache it in the engagement DB (`kev_cache` table) with a 24h TTL rather
than re-fetching per CVE.
"""

from __future__ import annotations

import json
import sqlite3

import httpx

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# How long a cached KEV catalog stays fresh before we re-download it.
KEV_TTL_HOURS = 24


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


def enrich_finding(conn: sqlite3.Connection, cve_id: str, kev_ids: set[str]) -> dict:
    """Compute enrichment for one CVE: its EPSS score and KEV membership.

    `kev_ids` is passed in (fetched once per run via get_kev_ids) so we don't
    re-resolve the catalog for every finding. Only EPSS is a per-CVE call.
    Returns {"epss_score": float|None, "kev": 0|1}.
    """
    score = query_epss(cve_id)
    return {"epss_score": score, "kev": 1 if cve_id in kev_ids else 0}
