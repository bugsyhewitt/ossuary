"""Command-line interface for ossuary.

Subcommands (v0.1):

    init         create the engagement SQLite DB and its tables
    discover     ping/host-discover targets -> assets table
    fingerprint  service/version detect known assets -> services table
    match-cves   query OSV.dev for service versions -> findings table
    cruise       re-fingerprint, diff against last state, report changes
    dump         export full engagement state as JSON
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, cruise as cruise_mod, cves, db, discover as discover_mod
from . import dump as dump_mod, fingerprint as fingerprint_mod


def _add_db_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--db",
        required=True,
        metavar="PATH",
        help="path to the engagement SQLite database file",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ossuary",
        description=(
            "SQLite-backed local network asset inventory and cruise scanner "
            "for solo bug bounty engagements."
        ),
    )
    parser.add_argument("--version", action="version", version=f"ossuary {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p_init = sub.add_parser("init", help="create the engagement DB and tables")
    _add_db_arg(p_init)

    p_discover = sub.add_parser("discover", help="host-discover targets into assets")
    _add_db_arg(p_discover)
    p_discover.add_argument(
        "--targets",
        required=True,
        metavar="PATH",
        help="path to a targets file (one IP/CIDR/hostname per line)",
    )

    p_fp = sub.add_parser("fingerprint", help="service/version detect known assets")
    _add_db_arg(p_fp)

    p_match = sub.add_parser(
        "match-cves", help="query OSV.dev (and optionally NVD) for service versions"
    )
    _add_db_arg(p_match)
    p_match.add_argument(
        "--source",
        default="osv",
        choices=["osv", "nvd", "both"],
        help=(
            "vulnerability database(s) to query: osv (default), nvd, or both. "
            "CPE-derived product names are used when a service has a CPE; NVD is "
            "queried by cpeName/keywordSearch and results are deduplicated by CVE"
        ),
    )
    p_match.add_argument(
        "--nvd-api-key",
        default=None,
        metavar="KEY",
        help=(
            "NVD API key (raises the rate ceiling from 5 to 50 req/30s); only "
            "used when --source is nvd or both"
        ),
    )
    p_match.add_argument(
        "--enrich",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "annotate findings with EPSS exploit-probability (FIRST) and CISA "
            "KEV status (default: enabled; use --no-enrich to skip the lookups)"
        ),
    )

    p_cruise = sub.add_parser(
        "cruise", help="re-fingerprint and diff against last saved state"
    )
    _add_db_arg(p_cruise)

    p_dump = sub.add_parser("dump", help="export full engagement state")
    _add_db_arg(p_dump)
    p_dump.add_argument(
        "--format",
        default="json",
        choices=["json"],
        help="output format (v0.1: json only)",
    )

    return parser


def _cmd_init(args: argparse.Namespace) -> int:
    conn = db.init_db(args.db)
    conn.close()
    print(f"initialised engagement database at {args.db}")
    print(f"tables: {', '.join(db.EXPECTED_TABLES)}")
    return 0


def _cmd_discover(args: argparse.Namespace) -> int:
    count = discover_mod.discover(args.db, args.targets)
    print(f"discovered {count} live asset(s) -> {args.db}")
    return 0


def _cmd_fingerprint(args: argparse.Namespace) -> int:
    count = fingerprint_mod.fingerprint(args.db)
    print(f"fingerprinted {count} service(s) -> {args.db}")
    return 0


def _format_finding(row: dict) -> str:
    """Render one finding row as a single severity-context line.

    Shows the OSV/NVD severity (often blank for fresh CVEs since NIST's
    enrichment retreat) alongside the restored signal: EPSS exploit probability
    and CISA KEV status.
    """
    severity = row["severity"] or "—"
    epss = row["epss_score"]
    epss_str = f"{epss:.2f}" if epss is not None else "—"
    kev_str = "YES" if row["kev"] else "no"
    return (
        f"  {row['cve_id']}  severity: {severity}  "
        f"EPSS: {epss_str} | KEV: {kev_str}"
    )


def _cmd_match_cves(args: argparse.Namespace) -> int:
    count = cves.match_cves(
        args.db,
        enrich_findings=args.enrich,
        source=args.source,
        nvd_api_key=args.nvd_api_key,
    )
    print(f"matched {count} finding(s) -> {args.db}")
    if count:
        conn = db.require_initialised(args.db)
        try:
            rows = conn.execute(
                "SELECT cve_id, severity, epss_score, kev FROM findings "
                "ORDER BY kev DESC, epss_score DESC NULLS LAST, cve_id"
            ).fetchall()
        finally:
            conn.close()
        for row in rows:
            print(_format_finding(row))
    return 0


def _cmd_cruise(args: argparse.Namespace) -> int:
    diff = cruise_mod.cruise(args.db)
    n_added = len(diff["added"])
    n_removed = len(diff["removed"])
    n_changed = len(diff["changed"])
    print(
        f"cruise diff: {n_added} added, {n_removed} removed, {n_changed} changed"
    )
    print(json.dumps(diff, indent=2))
    return 0


def _cmd_dump(args: argparse.Namespace) -> int:
    print(dump_mod.dump(args.db, args.format))
    return 0


_DISPATCH = {
    "init": _cmd_init,
    "discover": _cmd_discover,
    "fingerprint": _cmd_fingerprint,
    "match-cves": _cmd_match_cves,
    "cruise": _cmd_cruise,
    "dump": _cmd_dump,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = _DISPATCH[args.command]
    try:
        return handler(args)
    except (RuntimeError, ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
