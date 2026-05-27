"""Vulnerability matching for ossuary, backed by OSV.dev (and optionally NVD).

For each fingerprinted service that has a product + version, query OSV.dev for
known vulnerabilities and persist matches into the `findings` table.

`query_osv` and `query_nvd` are the two network seams mocked in tests — they are
the only functions that perform HTTP. Note: ossuary is the *inventory* layer. It
records that a CVE *may* apply to a discovered version. Active verification is
miasma's job, not ours (explicitly NOT-in-v0.1).

CPE-aware querying
------------------
nmap ``-sV`` populates the ``services.cpe`` column with a CPE 2.3 URI such as
``cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*``. The product field (index 4) is a
more precise package identifier than the free-text nmap service ``product``
name, so when a CPE is present we use the CPE-derived product for the OSV query
and fall back to the raw nmap product name otherwise.

Multi-source matching
----------------------
``--source`` selects which databases to query: ``osv`` (default), ``nvd``, or
``both``. NVD's CVE API v2 is queried by ``cpeName`` when a CPE is available, or
by ``keywordSearch`` on the product otherwise. Results from both sources are
deduplicated by CVE id before being persisted (OSV wins ties since it carries
structured severity more reliably for non-federal CVEs).
"""

from __future__ import annotations

import time
from pathlib import Path

import httpx

from . import db, enrich

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
NVD_QUERY_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD rate limits: 5 requests / 30s without an API key, 50 / 30s with one. We
# stay comfortably under the unauthenticated ceiling by sleeping ~0.6s between
# calls; with a key the window is 10x larger so a 0.6/10 sleep suffices.
NVD_SLEEP_NO_KEY = 0.6
NVD_SLEEP_WITH_KEY = 0.06


def extract_cpe_product(cpe: str | None) -> str | None:
    """Extract the product name (field 4) from a CPE 2.3 URI string.

    A CPE 2.3 formatted string looks like::

        cpe:2.3:a:<vendor>:<product>:<version>:...

    Returns the ``<product>`` component, or None when the string is missing,
    not CPE 2.3, or has no product field. CPE escaping (``\\:`` etc.) is left
    intact since OSV/NVD expect the raw component; a bare ``*`` (ANY) product
    is treated as absent.
    """
    if not cpe:
        return None
    parts = cpe.split(":")
    # cpe:2.3:<part>:<vendor>:<product>:... -> product is index 4.
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    product = parts[4].strip()
    if not product or product == "*":
        return None
    return product


def resolve_product(nmap_product: str | None, cpe: str | None) -> str | None:
    """Pick the most precise product identifier for a service.

    Prefers the CPE-derived product (more precise, vendor-normalised) and falls
    back to the free-text nmap ``product`` name when no usable CPE is present.
    """
    return extract_cpe_product(cpe) or nmap_product


def query_osv(product: str, version: str) -> dict:
    """Query OSV.dev for vulnerabilities affecting product@version.

    Returns the parsed JSON response dict. Network seam — mocked in tests.

    [Worker decision: OSV's primary key is package ecosystem+name. We send the
    (CPE-derived where available) product name + version under a generic query
    payload. OSV's native CPE/purl path is beta-quality (issue #410), so rather
    than depend on it we extract the product from the CPE ourselves upstream and
    feed OSV the cleaner identifier — same reliability, no beta dependency.]
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


def query_nvd(
    cpe: str | None, product: str | None, api_key: str | None = None
) -> dict:
    """Query NVD's CVE API v2 for a service.

    Uses ``cpeName`` when a CPE is available (most precise), else falls back to
    ``keywordSearch`` on the product name. The ``apiKey`` header is sent when a
    key is supplied (raises the rate ceiling to 50 req/30s). Returns the parsed
    JSON response dict. Network seam — mocked in tests.
    """
    params: dict[str, str] = {}
    if cpe:
        params["cpeName"] = cpe
    elif product:
        params["keywordSearch"] = product
    headers = {"apiKey": api_key} if api_key else {}
    resp = httpx.get(NVD_QUERY_URL, params=params, headers=headers, timeout=30.0)
    resp.raise_for_status()
    return resp.json()


def parse_nvd_response(response: dict) -> list[dict]:
    """Extract findings from an NVD CVE API v2 response.

    The v2 schema nests each result under ``vulnerabilities[].cve`` with the id
    at ``cve.id``, the English description under ``cve.descriptions``, and CVSS
    scores under ``cve.metrics`` (preferring v3.1 > v3.0 > v2). Returns a list
    of {"cve_id", "summary", "severity"} dicts.
    """
    findings: list[dict] = []
    for item in response.get("vulnerabilities", []) or []:
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        summary = None
        for desc in cve.get("descriptions", []) or []:
            if desc.get("lang") == "en":
                summary = desc.get("value")
                break
        findings.append(
            {
                "cve_id": cve_id,
                "summary": summary,
                "severity": _nvd_severity(cve.get("metrics") or {}),
            }
        )
    return findings


def _nvd_severity(metrics: dict) -> str | None:
    """Pull the best available CVSS base score string from NVD metrics."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData") or {}
            score = data.get("baseScore")
            if score is not None:
                return str(score)
    return None


def _merge_findings(*sources: list[dict]) -> list[dict]:
    """Deduplicate findings by CVE id across one or more source lists.

    Earlier sources win on conflict (we pass OSV first), but a later source can
    fill in a field the earlier one left blank (e.g. NVD supplies a severity OSV
    lacked). Preserves first-seen order.
    """
    merged: dict[str, dict] = {}
    for source in sources:
        for finding in source:
            cve_id = finding["cve_id"]
            if cve_id not in merged:
                merged[cve_id] = dict(finding)
            else:
                existing = merged[cve_id]
                for field in ("summary", "severity"):
                    if existing.get(field) is None and finding.get(field) is not None:
                        existing[field] = finding[field]
    return list(merged.values())


def match_cves(
    db_path: str | Path,
    enrich_findings: bool = True,
    source: str = "osv",
    nvd_api_key: str | None = None,
) -> int:
    """Match all fingerprinted services against OSV.dev (and optionally NVD).

    Only services with both a product and a version are queried. The product
    used for OSV is CPE-derived when a CPE is present, else the nmap product
    name. Returns the number of finding rows written/updated.

    ``source`` selects the database(s): ``osv`` (default), ``nvd``, or ``both``.
    Findings from multiple sources are deduplicated by CVE id before persisting.
    NVD calls are rate-limited with a small sleep between requests (0.6s without
    an API key, 0.06s with one) to respect NVD's published ceilings.

    When ``enrich_findings`` is True (the default), each matched CVE is annotated
    with its EPSS exploit-probability score (FIRST) and CISA KEV status.
    """
    if source not in ("osv", "nvd", "both"):
        raise ValueError(f"unknown source {source!r}; expected osv, nvd, or both")
    use_osv = source in ("osv", "both")
    use_nvd = source in ("nvd", "both")
    nvd_sleep = NVD_SLEEP_WITH_KEY if nvd_api_key else NVD_SLEEP_NO_KEY

    conn = db.require_initialised(db_path)
    try:
        services = conn.execute(
            "SELECT id, product, version, cpe FROM services "
            "WHERE product IS NOT NULL AND version IS NOT NULL"
        ).fetchall()

        # Resolve the KEV id set once for the whole run (cached, TTL'd). Only
        # touched when we actually have findings to enrich.
        kev_ids: set[str] = set()
        kev_loaded = False

        total = 0
        for svc in services:
            cpe = svc["cpe"]
            product = resolve_product(svc["product"], cpe)
            osv_findings: list[dict] = []
            nvd_findings: list[dict] = []

            if use_osv and product:
                osv_findings = parse_osv_response(query_osv(product, svc["version"]))
            if use_nvd:
                nvd_findings = parse_nvd_response(
                    query_nvd(cpe, product, api_key=nvd_api_key)
                )
                # Respect NVD's rate limit between successive NVD requests.
                time.sleep(nvd_sleep)

            source_label = {
                "osv": "osv.dev",
                "nvd": "nvd",
                "both": "osv.dev+nvd",
            }[source]

            for finding in _merge_findings(osv_findings, nvd_findings):
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
                    source=source_label,
                    epss_score=epss_score,
                    kev=kev,
                )
                total += 1
        conn.commit()
    finally:
        conn.close()
    return total
