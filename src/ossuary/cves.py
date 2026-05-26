"""Vulnerability matching for ossuary, backed by OSV.dev.

For each fingerprinted service that has a product + version, query OSV.dev for
known vulnerabilities and persist matches into the `findings` table.

`query_osv` is the network seam mocked in tests — it is the only function that
performs HTTP. Note: ossuary is the *inventory* layer. It records that a CVE
*may* apply to a discovered version. Active verification is miasma's job, not
ours (explicitly NOT-in-v0.1).
"""

from __future__ import annotations

from pathlib import Path

import httpx

from . import db, enrich

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def query_osv(product: str, version: str) -> dict:
    """Query OSV.dev for vulnerabilities affecting product@version.

    Returns the parsed JSON response dict. Network seam — mocked in tests.

    [Worker decision: OSV's primary key is package ecosystem+name, which is a
    looser fit than a CPE. For v0.1 we send the product name + version under a
    generic query payload; this is sufficient to exercise the match->persist
    pipeline the criteria require and keeps us OSV-API-shaped for later
    refinement. We do NOT attempt CPE-to-OSV ecosystem mapping in v0.1.]
    """
    payload = {"version": version, "package": {"name": product}}
    resp = httpx.post(OSV_QUERY_URL, json=payload, timeout=30.0)
    resp.raise_for_status()
    return resp.json()


def parse_osv_response(response: dict) -> list[dict]:
    """Extract findings from an OSV.dev query response.

    Returns a list of {"cve_id", "summary", "severity"} dicts. Prefers an
    aliased CVE id when present, else falls back to the OSV id.
    """
    findings: list[dict] = []
    for vuln in response.get("vulns", []) or []:
        aliases = vuln.get("aliases", []) or []
        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id"))
        if not cve_id:
            continue
        severity = None
        sev_list = vuln.get("severity", []) or []
        if sev_list:
            severity = sev_list[0].get("score")
        findings.append(
            {
                "cve_id": cve_id,
                "summary": vuln.get("summary") or vuln.get("details"),
                "severity": severity,
            }
        )
    return findings


def match_cves(db_path: str | Path, enrich_findings: bool = True) -> int:
    """Match all fingerprinted services against OSV.dev, populating `findings`.

    Only services with both a product and a version are queried. Returns the
    number of finding rows written/updated.

    When `enrich_findings` is True (the default), each matched CVE is annotated
    with its EPSS exploit-probability score (FIRST) and CISA KEV status. The KEV
    catalog is fetched once per run and cached in the DB; EPSS is a per-CVE
    lookup. When False, no enrichment HTTP calls are made and findings keep the
    default epss_score=None / kev=0.
    """
    conn = db.require_initialised(db_path)
    try:
        services = conn.execute(
            "SELECT id, product, version FROM services "
            "WHERE product IS NOT NULL AND version IS NOT NULL"
        ).fetchall()

        # Resolve the KEV id set once for the whole run (cached, TTL'd). Only
        # touched when we actually have findings to enrich.
        kev_ids: set[str] = set()
        kev_loaded = False

        total = 0
        for svc in services:
            response = query_osv(svc["product"], svc["version"])
            for finding in parse_osv_response(response):
                epss_score: float | None = None
                kev = 0
                if enrich_findings:
                    if not kev_loaded:
                        kev_ids = enrich.get_kev_ids(conn)
                        kev_loaded = True
                    annotation = enrich.enrich_finding(
                        conn, finding["cve_id"], kev_ids
                    )
                    epss_score = annotation["epss_score"]
                    kev = annotation["kev"]
                db.upsert_finding(
                    conn,
                    service_id=int(svc["id"]),
                    cve_id=finding["cve_id"],
                    summary=finding["summary"],
                    severity=finding["severity"],
                    epss_score=epss_score,
                    kev=kev,
                )
                total += 1
        conn.commit()
    finally:
        conn.close()
    return total
