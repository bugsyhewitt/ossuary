"""HTTP/web layer discovery for ossuary.

For each asset that has an open TCP port in {80, 443, 8080, 8443}, sends
an HTTP HEAD (falling back to GET if HEAD returns 405) and stores the
response in the ``web_probes`` table.

Tech fingerprinting is done by simple pattern matching against response
headers and the HTML ``<title>`` — no external dependencies required.

The network seam is ``http_probe``; tests monkeypatch it so no real HTTP
requests are made.
"""

from __future__ import annotations

import json
import re
import ssl
from pathlib import Path
from typing import NamedTuple

import httpx

from . import db

# Ports we consider "web" ports.
WEB_PORTS = {80, 443, 8080, 8443}

# Ports where we try HTTPS first.
HTTPS_FIRST_PORTS = {443, 8443}

# Maximum redirects to follow and record.
MAX_REDIRECTS = 3


class ProbeResult(NamedTuple):
    """Result of a single HTTP probe attempt."""
    protocol: str
    status_code: int | None
    server: str | None
    title: str | None
    redirect_chain: list[str]   # list of URLs encountered during redirects
    tech_fingerprints: list[str]
    error: str | None = None


# ---------------------------------------------------------------------------
# Tech fingerprinting patterns
# ---------------------------------------------------------------------------

def _fingerprint_headers(headers: dict[str, str]) -> list[str]:
    """Extract technology signals from HTTP response headers.

    ``headers`` should be a case-insensitive dict or a plain dict with
    lowercased keys (httpx provides case-insensitive access).
    """
    techs: list[str] = []

    def header(name: str) -> str:
        return headers.get(name, "") if isinstance(headers, dict) else (headers.get(name) or "")

    server = header("server").lower()
    if "nginx" in server:
        techs.append("nginx")
    if "apache" in server:
        techs.append("apache")
    if "iis" in server:
        techs.append("iis")
    if "lighttpd" in server:
        techs.append("lighttpd")
    if "caddy" in server:
        techs.append("caddy")

    powered_by = header("x-powered-by").lower()
    if "php" in powered_by:
        techs.append("php")
    if "asp.net" in powered_by:
        techs.append("asp.net")
    if "express" in powered_by:
        techs.append("express")

    if header("x-aspnet-version"):
        if "asp.net" not in techs:
            techs.append("asp.net")
    if header("x-aspnetmvc-version"):
        if "asp.net" not in techs:
            techs.append("asp.net")

    generator = header("x-generator").lower()
    if "wordpress" in generator:
        techs.append("wordpress")
    if "drupal" in generator:
        techs.append("drupal")

    if header("x-drupal-cache") or header("x-drupal-dynamic-cache"):
        if "drupal" not in techs:
            techs.append("drupal")

    set_cookie = header("set-cookie").lower()
    if "jsessionid" in set_cookie:
        techs.append("java/tomcat")
    if "phpsessid" in set_cookie:
        if "php" not in techs:
            techs.append("php")
    if "laravel_session" in set_cookie:
        techs.append("laravel")

    if header("x-shopify-stage") or header("x-shopid"):
        techs.append("shopify")

    if header("x-wp-total") or header("x-wp-totalpages"):
        if "wordpress" not in techs:
            techs.append("wordpress")

    return techs


def _fingerprint_html(html: str, techs: list[str]) -> list[str]:
    """Augment tech list with signals from HTML body."""
    techs = list(techs)  # copy
    lower = html.lower()

    if 'name="generator" content="wordpress' in lower or "wp-content/" in lower:
        if "wordpress" not in techs:
            techs.append("wordpress")
    if 'name="generator" content="drupal' in lower or "drupal.settings" in lower:
        if "drupal" not in techs:
            techs.append("drupal")
    if "joomla" in lower and 'name="generator"' in lower:
        if "joomla" not in techs:
            techs.append("joomla")

    return techs


def _extract_title(html: str) -> str | None:
    """Extract the first <title> tag content from HTML."""
    m = re.search(r"<title[^>]*>([^<]{0,256})</title>", html, re.IGNORECASE)
    if m:
        return m.group(1).strip() or None
    return None


# ---------------------------------------------------------------------------
# Versioned tech extraction (for CVE matching)
# ---------------------------------------------------------------------------

# Maps the lowercased product token a server / x-powered-by banner uses to the
# OSV/NVD-friendly product identifier ossuary should query CVEs against. Keys
# are matched case-insensitively against the leading token of a "name/version"
# banner fragment (e.g. "Apache/2.4.51" -> token "apache").
_BANNER_PRODUCT_MAP = {
    "nginx": "nginx",
    "apache": "http_server",   # NVD/CPE call Apache httpd "http_server"
    "openssl": "openssl",
    "php": "php",
    "iis": "iis",
    "microsoft-iis": "iis",
    "lighttpd": "lighttpd",
    "caddy": "caddy",
    "tomcat": "tomcat",
    "jetty": "jetty",
    "express": "express",
    "werkzeug": "werkzeug",
    "gunicorn": "gunicorn",
    "node.js": "node.js",
    "nodejs": "node.js",
}

# A "<product>/<version>" banner fragment, e.g. "nginx/1.24.0" or "PHP/8.1.2".
# Version must start with a digit; we keep dotted numerics and trailing build
# tags up to the first whitespace / parenthesis.
_BANNER_FRAGMENT = re.compile(
    r"(?P<product>[A-Za-z][A-Za-z0-9._+-]*)/(?P<version>\d[\w.+-]*)"
)


def extract_versioned_techs(*banners: str | None) -> list[tuple[str, str]]:
    """Parse ``(product, version)`` pairs from HTTP banner header values.

    Accepts one or more banner strings (typically the ``Server`` and
    ``X-Powered-By`` header values). Each ``<name>/<version>`` fragment whose
    name maps to a known product in :data:`_BANNER_PRODUCT_MAP` yields a
    ``(osv_product, version)`` tuple. Unknown names and version-less banners are
    ignored. Duplicate pairs are collapsed; first-seen order is preserved.

    Examples::

        extract_versioned_techs("nginx/1.24.0")            -> [("nginx", "1.24.0")]
        extract_versioned_techs("Apache/2.4.51 (Ubuntu)")  -> [("http_server", "2.4.51")]
        extract_versioned_techs("PHP/8.1.2")               -> [("php", "8.1.2")]
        extract_versioned_techs("nginx")                   -> []   (no version)
    """
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for banner in banners:
        if not banner:
            continue
        for m in _BANNER_FRAGMENT.finditer(banner):
            token = m.group("product").lower()
            product = _BANNER_PRODUCT_MAP.get(token)
            if not product:
                continue
            version = m.group("version")
            pair = (product, version)
            if pair not in seen:
                seen.add(pair)
                pairs.append(pair)
    return pairs


# ---------------------------------------------------------------------------
# HTTP probe (network seam)
# ---------------------------------------------------------------------------

def http_probe(
    host: str,
    port: int,
    protocol: str,
    timeout: float = 10.0,
) -> ProbeResult:
    """Send HEAD (falling back to GET) to ``protocol://host:port/``.

    Returns a :class:`ProbeResult`. This is the network seam — tests
    monkeypatch this function so no real HTTP calls are made.

    Follows up to MAX_REDIRECTS hops and records the chain.  On SSL
    errors the caller should retry with ``protocol='http'``.
    """
    base_url = f"{protocol}://{host}:{port}"
    url = base_url + "/"

    redirect_chain: list[str] = []
    status_code: int | None = None
    server: str | None = None
    title: str | None = None
    techs: list[str] = []
    response_headers: dict = {}
    html_body: str = ""

    try:
        # Follow redirects manually so we can capture the chain.
        with httpx.Client(
            verify=False,
            follow_redirects=False,
            timeout=timeout,
        ) as client:
            current_url = url
            for _ in range(MAX_REDIRECTS + 1):
                try:
                    resp = client.head(current_url)
                except httpx.UnsupportedProtocol:
                    raise
                except Exception:
                    raise

                if resp.status_code == 405:
                    # HEAD not allowed — retry with GET, same URL, no redirect loop.
                    resp = client.get(current_url)

                status_code = resp.status_code
                response_headers = dict(resp.headers)
                server = resp.headers.get("server")

                # Redirect?
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if location:
                        redirect_chain.append(location)
                        # Make location absolute if relative.
                        if location.startswith("/"):
                            location = f"{protocol}://{host}:{port}{location}"
                        current_url = location
                        continue
                break

            # Fetch body if we don't have it yet (from GET above, or do a GET).
            # Only do a body fetch for text responses.
            content_type = response_headers.get("content-type", "")
            if "text/html" in content_type or "text/plain" in content_type:
                try:
                    body_resp = client.get(current_url)
                    html_body = body_resp.text[:65536]  # cap at 64 KiB
                    if body_resp.status_code == 405:
                        html_body = ""
                except Exception:
                    html_body = ""

        techs = _fingerprint_headers(response_headers)
        if html_body:
            title = _extract_title(html_body)
            techs = _fingerprint_html(html_body, techs)

        return ProbeResult(
            protocol=protocol,
            status_code=status_code,
            server=server,
            title=title,
            redirect_chain=redirect_chain,
            tech_fingerprints=techs,
        )

    except ssl.SSLError as exc:
        return ProbeResult(
            protocol=protocol,
            status_code=None,
            server=None,
            title=None,
            redirect_chain=[],
            tech_fingerprints=[],
            error=f"ssl_error: {exc}",
        )
    except httpx.ConnectError as exc:
        return ProbeResult(
            protocol=protocol,
            status_code=None,
            server=None,
            title=None,
            redirect_chain=[],
            tech_fingerprints=[],
            error=f"connect_error: {exc}",
        )
    except Exception as exc:
        return ProbeResult(
            protocol=protocol,
            status_code=None,
            server=None,
            title=None,
            redirect_chain=[],
            tech_fingerprints=[],
            error=f"error: {exc}",
        )


# ---------------------------------------------------------------------------
# Upsert helper
# ---------------------------------------------------------------------------

def upsert_web_probe(
    conn,
    asset_id: int,
    port: int,
    protocol: str,
    result: ProbeResult,
) -> None:
    """INSERT OR REPLACE a web_probes row for (asset_id, port, protocol)."""
    conn.execute(
        """
        INSERT INTO web_probes
            (asset_id, port, protocol, status_code, server, title,
             redirect_chain, tech_fingerprints)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(asset_id, port, protocol) DO UPDATE SET
            status_code       = excluded.status_code,
            server            = excluded.server,
            title             = excluded.title,
            redirect_chain    = excluded.redirect_chain,
            tech_fingerprints = excluded.tech_fingerprints,
            probed_at         = datetime('now')
        """,
        (
            asset_id,
            port,
            protocol,
            result.status_code,
            result.server,
            result.title,
            json.dumps(result.redirect_chain),
            json.dumps(result.tech_fingerprints),
        ),
    )


# ---------------------------------------------------------------------------
# Main probe entry point
# ---------------------------------------------------------------------------

def probe(
    db_path: str | Path,
    host_filter: str | None = None,
    timeout: float = 10.0,
    ports: set[int] | None = None,
) -> int:
    """Probe all assets with open web ports; persist results to web_probes.

    Returns the number of probe rows written.
    """
    if ports is None:
        ports = WEB_PORTS

    conn = db.require_initialised(db_path)
    try:
        # Fetch assets with qualifying services.
        placeholders = ",".join("?" * len(ports))
        query = f"""
            SELECT DISTINCT a.id AS asset_id,
                            COALESCE(a.hostname, a.ip) AS host,
                            a.ip,
                            s.port
            FROM assets a
            JOIN services s ON s.asset_id = a.id
            WHERE s.port IN ({placeholders})
              AND s.protocol = 'tcp'
        """
        params: list = list(ports)
        if host_filter:
            query += " AND (a.ip = ? OR a.hostname = ?)"
            params += [host_filter, host_filter]
        query += " ORDER BY a.id, s.port"

        rows = conn.execute(query, params).fetchall()

        written = 0
        for row in rows:
            asset_id = row["asset_id"]
            host = row["host"]
            port = row["port"]

            # Choose protocol order: HTTPS first for 443/8443.
            if port in HTTPS_FIRST_PORTS:
                protocol_order = ["https", "http"]
            else:
                protocol_order = ["http", "https"]

            result = None
            for protocol in protocol_order:
                r = http_probe(host, port, protocol, timeout=timeout)
                if r.error and ("ssl_error" in r.error or "connect_error" in r.error):
                    # SSL failure: try next protocol.
                    continue
                result = r
                break

            if result is None:
                # Both protocols failed; record the last error with the first protocol.
                result = http_probe.__wrapped__(host, port, protocol_order[0], timeout=timeout) \
                    if hasattr(http_probe, "__wrapped__") else ProbeResult(
                        protocol=protocol_order[0],
                        status_code=None,
                        server=None,
                        title=None,
                        redirect_chain=[],
                        tech_fingerprints=[],
                        error="all_protocols_failed",
                    )

            upsert_web_probe(conn, asset_id, port, result.protocol, result)
            conn.commit()
            written += 1

            # Print summary line.
            techs_str = ", ".join(result.tech_fingerprints) if result.tech_fingerprints else "—"
            status_str = str(result.status_code) if result.status_code else "err"
            print(f"{host}:{port} → {status_str} ({techs_str})")

        return written
    finally:
        conn.close()
