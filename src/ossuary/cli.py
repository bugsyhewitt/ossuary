"""Command-line interface for ossuary.

Subcommands (v0.1):

    init         create the engagement SQLite DB and its tables
    discover     ping/host-discover targets -> assets table
    fingerprint  service/version detect known assets -> services table
    match-cves   query OSV.dev for service versions -> findings table
    cruise       re-fingerprint, diff against last state, report changes
    watch        run cruise on an interval, emitting a diff summary each pass
    dump         export full engagement state as JSON, CSV, Markdown, HTML, or SARIF
    stats        print a top-of-funnel engagement summary (counts + top hits)
    stale        flag findings not re-confirmed within N days (age staleness)
    diff         compare two engagement DBs -> new / resolved / persisting findings
    profiles     list the named scan profiles (stealth/aggressive/web/default)

Discover, fingerprint, and cruise accept a `--profile NAME` flag selecting a
named nmap flag preset; the chosen profile is recorded on each asset/service row.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, cruise as cruise_mod, cves, db, discover as discover_mod
from . import dump as dump_mod, fingerprint as fingerprint_mod, probe as probe_mod
from . import findingdiff as findingdiff_mod, profiles as profiles_mod
from . import stale as stale_mod, stats as stats_mod, tags as tags_mod
from . import watch as watch_mod


def _add_db_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--db",
        required=True,
        metavar="PATH",
        help="path to the engagement SQLite database file",
    )


def _add_profile_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--profile",
        default=profiles_mod.DEFAULT_PROFILE,
        choices=profiles_mod.profile_names(),
        metavar="NAME",
        help=(
            "named nmap flag preset to scan with (see `ossuary profiles`): "
            + ", ".join(profiles_mod.profile_names())
            + f" (default: {profiles_mod.DEFAULT_PROFILE})"
        ),
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
    _add_profile_arg(p_discover)

    p_fp = sub.add_parser("fingerprint", help="service/version detect known assets")
    _add_db_arg(p_fp)
    _add_profile_arg(p_fp)

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
    p_match.add_argument(
        "--web",
        action="store_true",
        help=(
            "also match versioned web tech fingerprints from the web_probes "
            "table (e.g. a Server: nginx/1.24.0 banner) against the selected "
            "source(s); findings attach to the owning TCP service. Run `ossuary "
            "probe` first to populate web_probes"
        ),
    )

    p_cruise = sub.add_parser(
        "cruise", help="re-fingerprint and diff against last saved state"
    )
    _add_db_arg(p_cruise)
    _add_profile_arg(p_cruise)

    sub.add_parser(
        "profiles", help="list the available named scan profiles and their nmap flags"
    )

    p_watch = sub.add_parser(
        "watch",
        help="run cruise on an interval, emitting a diff summary each pass",
    )
    _add_db_arg(p_watch)
    p_watch.add_argument(
        "--interval",
        default="4h",
        metavar="DURATION",
        help=(
            "time between cruise passes — an integer (seconds) or a value with "
            "an s/m/h/d suffix (default: 4h; e.g. 30m, 90s, 1d)"
        ),
    )
    p_watch.add_argument(
        "--notify",
        action="append",
        default=[],
        metavar="SINK",
        help=(
            "where to send each interval's diff summary; repeatable. "
            "file:<path> appends to a file, slack:<webhook> POSTs to a Slack "
            "incoming webhook. Webhook URLs are never written to the DB"
        ),
    )
    p_watch.add_argument(
        "--iterations",
        type=int,
        default=None,
        metavar="N",
        help="stop after N cruise passes (default: run until SIGTERM/SIGINT)",
    )
    p_watch.add_argument(
        "--once",
        action="store_true",
        help="run exactly one cruise pass then exit (shorthand for --iterations 1)",
    )
    p_watch.add_argument(
        "--quiet-when-unchanged",
        action="store_true",
        help="only emit a summary on passes where something actually changed",
    )

    p_dump = sub.add_parser("dump", help="export full engagement state")
    _add_db_arg(p_dump)
    p_dump.add_argument(
        "--format",
        default="json",
        choices=["json", "csv", "markdown", "html", "sarif"],
        help=(
            "output format: json (nested), csv or markdown (flat, one finding "
            "per row), html (self-contained report grouped per asset), or sarif "
            "(SARIF v2.1.0 for GitHub code scanning / DefectDojo / etc.)"
        ),
    )
    p_dump.add_argument(
        "--tag",
        default=None,
        metavar="LABEL",
        help="only export assets carrying this tag (see `ossuary tag`)",
    )
    p_dump.add_argument(
        "--min-epss",
        type=float,
        default=None,
        metavar="P",
        help=(
            "only export findings with an EPSS exploit-probability >= P (0-1); "
            "findings without an EPSS score are excluded"
        ),
    )
    p_dump.add_argument(
        "--min-severity",
        type=float,
        default=None,
        metavar="SCORE",
        help=(
            "only export findings with a numeric severity (CVSS) >= SCORE; "
            "blank/non-numeric severities are excluded"
        ),
    )
    p_dump.add_argument(
        "--kev-only",
        action="store_true",
        help="only export findings in CISA's Known Exploited Vulnerabilities catalog",
    )
    p_dump.add_argument(
        "--since",
        default=None,
        metavar="DATE",
        help=(
            "only export findings recorded (matched_at) on or after DATE "
            "(YYYY-MM-DD or 'YYYY-MM-DD HH:MM:SS'); inclusive"
        ),
    )
    p_dump.add_argument(
        "--until",
        default=None,
        metavar="DATE",
        help=(
            "only export findings recorded (matched_at) on or before DATE "
            "(YYYY-MM-DD or 'YYYY-MM-DD HH:MM:SS'); inclusive — a bare date "
            "covers the whole day"
        ),
    )
    p_dump.add_argument(
        "--sort-by-priority",
        action="store_true",
        help=(
            "order each service's findings KEV-first, then by descending EPSS, "
            "severity, and CVE id (the `match-cves` triage order) instead of "
            "alphabetically by CVE id"
        ),
    )

    p_stats = sub.add_parser(
        "stats", help="print an at-a-glance engagement summary (counts + top hits)"
    )
    _add_db_arg(p_stats)
    p_stats.add_argument(
        "--format",
        default="text",
        choices=["text", "json"],
        help="output format: text (human-readable) or json (same numbers)",
    )
    p_stats.add_argument(
        "--top",
        type=int,
        default=stats_mod.DEFAULT_TOP,
        metavar="N",
        help=(
            "how many leading findings to list, in match-cves triage order "
            f"(default: {stats_mod.DEFAULT_TOP}; 0 to omit the list)"
        ),
    )
    p_stats.add_argument(
        "--tag",
        default=None,
        metavar="LABEL",
        help=(
            "only summarise assets carrying this tag (the same scoping "
            "`dump --tag` applies; see `ossuary tag`)"
        ),
    )
    p_stats.add_argument(
        "--min-epss",
        type=float,
        default=None,
        metavar="P",
        help=(
            "only count findings with an EPSS exploit-probability >= P (0-1); "
            "findings without an EPSS score are excluded (the same filter "
            "`dump --min-epss` applies)"
        ),
    )
    p_stats.add_argument(
        "--min-severity",
        type=float,
        default=None,
        metavar="SCORE",
        help=(
            "only count findings with a numeric severity (CVSS) >= SCORE; "
            "blank/non-numeric severities are excluded (the same filter "
            "`dump --min-severity` applies)"
        ),
    )
    p_stats.add_argument(
        "--kev-only",
        action="store_true",
        help=(
            "only count findings in CISA's Known Exploited Vulnerabilities "
            "catalog (the same filter `dump --kev-only` applies)"
        ),
    )

    p_stale = sub.add_parser(
        "stale",
        help="flag findings not re-confirmed (matched_at) within N days",
    )
    _add_db_arg(p_stale)
    p_stale.add_argument(
        "--format",
        default="text",
        choices=["text", "json"],
        help="output format: text (human-readable) or json (same rows)",
    )
    p_stale.add_argument(
        "--max-age-days",
        type=float,
        default=stale_mod.DEFAULT_MAX_AGE_DAYS,
        metavar="DAYS",
        help=(
            "flag findings whose matched_at is older than DAYS "
            f"(default: {stale_mod.DEFAULT_MAX_AGE_DAYS}); findings with no "
            "matched_at are always flagged"
        ),
    )
    p_stale.add_argument(
        "--tag",
        default=None,
        metavar="LABEL",
        help=(
            "only consider assets carrying this tag (the same scoping "
            "`dump --tag` applies; see `ossuary tag`)"
        ),
    )
    p_stale.add_argument(
        "--min-epss",
        type=float,
        default=None,
        metavar="P",
        help=(
            "only consider findings with an EPSS exploit-probability >= P (0-1); "
            "the same filter `dump --min-epss` applies"
        ),
    )
    p_stale.add_argument(
        "--min-severity",
        type=float,
        default=None,
        metavar="SCORE",
        help=(
            "only consider findings with a numeric severity (CVSS) >= SCORE; "
            "the same filter `dump --min-severity` applies"
        ),
    )
    p_stale.add_argument(
        "--kev-only",
        action="store_true",
        help=(
            "only consider findings in CISA's Known Exploited Vulnerabilities "
            "catalog (the same filter `dump --kev-only` applies)"
        ),
    )

    p_diff = sub.add_parser(
        "diff",
        help="compare two engagement DBs to show new / resolved CVE findings",
    )
    p_diff.add_argument(
        "--db",
        required=True,
        metavar="PATH",
        help="baseline engagement DB (the earlier scan)",
    )
    p_diff.add_argument(
        "--against",
        required=True,
        metavar="PATH",
        help="current engagement DB to compare against the baseline (the later scan)",
    )
    p_diff.add_argument(
        "--format",
        default="text",
        choices=["text", "json"],
        help="output format: text (human-readable) or json (same structure)",
    )
    p_diff.add_argument(
        "--min-epss",
        type=float,
        default=None,
        metavar="P",
        help=(
            "only diff findings with an EPSS exploit-probability >= P (0-1) on "
            "each side; findings without an EPSS score are excluded (the same "
            "filter `dump --min-epss` applies)"
        ),
    )
    p_diff.add_argument(
        "--min-severity",
        type=float,
        default=None,
        metavar="SCORE",
        help=(
            "only diff findings with a numeric severity (CVSS) >= SCORE on each "
            "side; blank/non-numeric severities are excluded (the same filter "
            "`dump --min-severity` applies)"
        ),
    )
    p_diff.add_argument(
        "--kev-only",
        action="store_true",
        help=(
            "only diff findings in CISA's Known Exploited Vulnerabilities catalog "
            "on each side (the same filter `dump --kev-only` applies)"
        ),
    )

    p_probe = sub.add_parser(
        "probe", help="HTTP/web layer discovery — probe web ports on known assets"
    )
    _add_db_arg(p_probe)
    p_probe.add_argument(
        "--host",
        default=None,
        metavar="HOST",
        help="limit probing to a single host (IP or hostname)",
    )
    p_probe.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="per-request HTTP timeout in seconds (default: 10)",
    )
    p_probe.add_argument(
        "--ports",
        default="80,443,8080,8443",
        metavar="PORTS",
        help="comma-separated list of ports to probe (default: 80,443,8080,8443)",
    )

    p_tag = sub.add_parser(
        "tag", help="attach / list / remove labels on assets for grouping & filtering"
    )
    tag_sub = p_tag.add_subparsers(dest="tag_action", required=True, metavar="ACTION")

    p_tag_add = tag_sub.add_parser("add", help="attach a tag to an asset")
    _add_db_arg(p_tag_add)
    p_tag_add.add_argument(
        "--asset",
        required=True,
        metavar="IP",
        help="asset IP (or hostname) to tag — must already be discovered",
    )
    p_tag_add.add_argument(
        "--tag",
        required=True,
        metavar="LABEL",
        help='the label to attach (e.g. "in-scope", "vip", "env:prod")',
    )

    p_tag_list = tag_sub.add_parser("list", help="list tags, optionally filtered")
    _add_db_arg(p_tag_list)
    p_tag_list.add_argument(
        "--entity",
        default=None,
        choices=["asset", "service", "finding"],
        help="restrict to one entity kind (default: all)",
    )
    p_tag_list.add_argument(
        "--asset",
        default=None,
        metavar="IP",
        help="restrict to a single asset's tags (IP or hostname)",
    )

    p_tag_rm = tag_sub.add_parser("rm", help="remove a tag from an asset")
    _add_db_arg(p_tag_rm)
    p_tag_rm.add_argument(
        "--asset",
        required=True,
        metavar="IP",
        help="asset IP (or hostname) to untag",
    )
    p_tag_rm.add_argument(
        "--tag",
        required=True,
        metavar="LABEL",
        help="the label to remove",
    )

    return parser


def _cmd_init(args: argparse.Namespace) -> int:
    conn = db.init_db(args.db)
    conn.close()
    print(f"initialised engagement database at {args.db}")
    print(f"tables: {', '.join(db.EXPECTED_TABLES)}")
    return 0


def _cmd_discover(args: argparse.Namespace) -> int:
    count = discover_mod.discover(args.db, args.targets, profile=args.profile)
    print(f"discovered {count} live asset(s) [profile: {args.profile}] -> {args.db}")
    return 0


def _cmd_fingerprint(args: argparse.Namespace) -> int:
    count = fingerprint_mod.fingerprint(args.db, profile=args.profile)
    print(f"fingerprinted {count} service(s) [profile: {args.profile}] -> {args.db}")
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
    if args.web:
        web_count = cves.match_web_cves(
            args.db,
            enrich_findings=args.enrich,
            source=args.source,
            nvd_api_key=args.nvd_api_key,
        )
        print(f"matched {web_count} web finding(s) -> {args.db}")
        count += web_count
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
    diff = cruise_mod.cruise(args.db, profile=args.profile)
    n_added = len(diff["added"])
    n_removed = len(diff["removed"])
    n_changed = len(diff["changed"])
    n_tags = len(diff.get("tag_changes", []))
    n_profile = len(diff.get("profile_changes", []))
    print(
        f"cruise diff: {n_added} added, {n_removed} removed, "
        f"{n_changed} changed, {n_tags} tag change(s), "
        f"{n_profile} profile change(s)"
    )
    print(json.dumps(diff, indent=2))
    return 0


def _cmd_profiles(args: argparse.Namespace) -> int:
    for prof in profiles_mod.list_profiles():
        print(f"{prof.name}")
        print(f"  {prof.description}")
        print(f"  discover:    nmap {prof.discover}")
        print(f"  fingerprint: nmap {prof.fingerprint}")
    return 0


def _cmd_watch(args: argparse.Namespace) -> int:
    # Fail fast on the engagement DB and on bad flags before entering the loop.
    db.require_initialised(args.db).close()
    interval_seconds = watch_mod.parse_interval(args.interval)
    sinks = [watch_mod.parse_notify(spec) for spec in args.notify]

    iterations = args.iterations
    if args.once:
        iterations = 1

    config = watch_mod.WatchConfig(
        db_path=args.db,
        interval_seconds=interval_seconds,
        sinks=sinks,
        iterations=iterations,
        quiet_when_unchanged=args.quiet_when_unchanged,
    )

    horizon = "once" if iterations == 1 else (
        f"{iterations} pass(es)" if iterations is not None else "until interrupted"
    )
    print(
        f"watching {args.db} — cruise every {interval_seconds}s, {horizon} "
        f"({len(sinks)} notify sink(s))"
    )
    completed = watch_mod.watch(config)
    print(f"watch stopped after {completed} cruise pass(es)")
    return 0


def _cmd_dump(args: argparse.Namespace) -> int:
    print(
        dump_mod.dump(
            args.db,
            args.format,
            tag=args.tag,
            min_epss=args.min_epss,
            min_severity=args.min_severity,
            kev_only=args.kev_only,
            since=args.since,
            until=args.until,
            sort_by_priority=args.sort_by_priority,
        )
    )
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    print(
        stats_mod.stats(
            args.db,
            args.format,
            top=args.top,
            tag=args.tag,
            min_epss=args.min_epss,
            min_severity=args.min_severity,
            kev_only=args.kev_only,
        )
    )
    return 0


def _cmd_stale(args: argparse.Namespace) -> int:
    print(
        stale_mod.stale(
            args.db,
            args.format,
            max_age_days=args.max_age_days,
            tag=args.tag,
            min_epss=args.min_epss,
            min_severity=args.min_severity,
            kev_only=args.kev_only,
        )
    )
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    print(
        findingdiff_mod.diff(
            args.db,
            args.against,
            args.format,
            min_epss=args.min_epss,
            min_severity=args.min_severity,
            kev_only=args.kev_only,
        )
    )
    return 0


def _cmd_probe(args: argparse.Namespace) -> int:
    try:
        ports = {int(p.strip()) for p in args.ports.split(",") if p.strip()}
    except ValueError as exc:
        print(f"error: invalid --ports value: {exc}", file=sys.stderr)
        return 1
    count = probe_mod.probe(
        args.db,
        host_filter=args.host,
        timeout=args.timeout,
        ports=ports,
    )
    print(f"probed {count} web endpoint(s) -> {args.db}")
    return 0


def _cmd_tag(args: argparse.Namespace) -> int:
    if args.tag_action == "add":
        created = tags_mod.add_tag(args.db, args.asset, args.tag)
        if created:
            print(f"tagged {args.asset} with {args.tag!r} -> {args.db}")
        else:
            print(f"{args.asset} already carries {args.tag!r} (no change)")
        return 0
    if args.tag_action == "rm":
        removed = tags_mod.remove_tag(args.db, args.asset, args.tag)
        if removed:
            print(f"removed {args.tag!r} from {args.asset} -> {args.db}")
        else:
            print(f"{args.asset} had no tag {args.tag!r} (no change)")
        return 0
    # list
    rows = tags_mod.list_tags(args.db, entity=args.entity, asset=args.asset)
    if not rows:
        print("no tags")
        return 0
    for row in rows:
        selector = row["asset_ip"] or f"{row['entity']}#{row['entity_id']}"
        print(f"  {selector}\t{row['tag']}")
    return 0


_DISPATCH = {
    "init": _cmd_init,
    "discover": _cmd_discover,
    "fingerprint": _cmd_fingerprint,
    "match-cves": _cmd_match_cves,
    "cruise": _cmd_cruise,
    "watch": _cmd_watch,
    "dump": _cmd_dump,
    "stats": _cmd_stats,
    "stale": _cmd_stale,
    "diff": _cmd_diff,
    "probe": _cmd_probe,
    "tag": _cmd_tag,
    "profiles": _cmd_profiles,
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
