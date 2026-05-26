# ossuary — Post-v0.1 Directions

Research lap completed 2026-05-26. Ranked by impact:effort ratio for a solo
bug bounty hunter. Each item is scoped to one implementation lap.

---

## Rank 1 — EPSS + CISA KEV enrichment on findings

**What:** When a finding is written to the `findings` table, annotate it with
two additional columns — `epss_score REAL` (0–1 exploit probability for the
next 30 days, from the FIRST EPSS API) and `kev INTEGER` (1 if the CVE
appears in CISA's Known Exploited Vulnerabilities catalog, 0 otherwise). The
`match-cves` command gains a `--enrich` flag (default: on) that fetches both
enrichments. `dump` and `cruise` output already carry the full findings dict,
so no further changes needed to surface the data.

**Why now:** NIST shifted NVD to risk-based-only enrichment in April 2026;
~80–85% of new CVEs now receive no CVSS analysis from NIST. EPSS v4 (launched
March 2025) and the KEV catalog are the two machine-readable signals that let
hunters prioritize "likely exploited now" vs. "theoretically severe but cold."
Without this, ossuary's severity column is increasingly meaningless for new
CVEs. EPSS data is free, flat-file downloadable daily
(https://api.first.org/data/v1/epss), or queryable per CVE. KEV is a plain
JSON file from CISA, updated daily.

**Schema change:**

```sql
ALTER TABLE findings ADD COLUMN epss_score REAL;
ALTER TABLE findings ADD COLUMN kev INTEGER NOT NULL DEFAULT 0;
```

**Effort:** Small. Two additional HTTP calls per CVE at match time (or one
bulk lookup against a locally-cached EPSS file). No new dependencies beyond
`httpx` already in use.

---

## Rank 2 — OSV.dev CPE-aware querying + multi-source fallback

**What:** Improve `match-cves` to use the CPE already stored in the `services`
table (populated by nmap `-sV`) to build a more precise OSV query. Currently
the payload sends `{"package": {"name": product}}` — a generic name match.
OSV has CPE-based matching in beta (issue #410); add a CPE path with graceful
fallback to the current name query. As a second source, add optional NVD CVE
API v2 lookup (`https://services.nvd.nist.gov/rest/json/cves/2.0`) via
`--source nvd` flag so hunters can cross-reference. 

**Why now:** OSV made its API 2.5× faster in 2025. The CPE column is already
in the schema and populated by nmap — using it costs no extra discovery work.
Given NVD's enrichment retreat, the OSV+CPE path is more reliable for
non-KEV/non-federal CVEs than NVD. Adding NVD as an optional fallback covers
the CISA KEV / critical-software tier that NVD still enriches promptly.

**Effort:** Medium. Requires CPE-to-OSV-package mapping logic and a secondary
HTTP client path. OSV's CPE support is beta-quality; needs a robust fallback.

---

## Rank 3 — HTTP/web layer discovery (`ossuary probe`)

**What:** Add an `ossuary probe` subcommand that, for each asset with an open
TCP port in {80, 443, 8080, 8443, 8888, …}, sends an HTTP HEAD (then GET if
needed) and stores the response in a new `web_probes` table:
`status_code, server_header, title, redirect_chain, tech_fingerprints (JSON),
probed_at`. Tech fingerprinting uses
`projectdiscovery/wappalyzergo`-style pattern matching (header + HTML regex)
to populate `tech_fingerprints`. Findings matching against web tech versions
can then run through `match-cves` just as nmap service versions do.

**Schema addition:**

```sql
CREATE TABLE IF NOT EXISTS web_probes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id     INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port         INTEGER NOT NULL,
    protocol     TEXT NOT NULL DEFAULT 'https',
    status_code  INTEGER,
    server       TEXT,
    title        TEXT,
    redirect_chain TEXT,
    tech_fingerprints TEXT,
    probed_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(asset_id, port, protocol)
);
```

**Why now:** The modern 2025–2026 bug bounty stack chains nmap → httpx →
Wappalyzer in every serious pipeline. ossuary stops at layer 4 (TCP services).
Hunters working web targets need layer 7 fingerprints in the same DB. `httpx`
is an external dep; ossuary can do this in pure Python with `httpx` (already
a dependency) + a bundled fingerprint JSON file (wappalyzer's patterns are MIT
licensed). No new mandatory dependencies.

**Effort:** Medium-high. The fingerprint pattern file is non-trivial to bundle
and maintain. Scope carefully to HTTP response headers + page `<title>` only
for v0.2; full HTML body pattern matching deferred to v0.3.

---

## Rank 4 — Asset tagging / label system

**What:** Add a `tags` table and an `ossuary tag` subcommand:

```sql
CREATE TABLE IF NOT EXISTS tags (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    entity   TEXT NOT NULL,   -- 'asset' | 'service' | 'finding'
    entity_id INTEGER NOT NULL,
    tag      TEXT NOT NULL,
    tagged_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(entity, entity_id, tag)
);
```

Commands:
```
ossuary tag add   --db <db> --asset 10.10.0.5 --tag "in-scope"
ossuary tag add   --db <db> --asset 10.10.0.5 --tag "priority"
ossuary tag list  --db <db> --entity asset
ossuary tag rm    --db <db> --asset 10.10.0.5 --tag "priority"
```

Tags flow into `dump` output and `cruise` diff output (changed tags appear in
a new `tag_changes` section of the diff).

**Why now:** Asset tagging is the missing workflow glue for bug bounty hunters
managing large programs with hundreds of in-scope/out-of-scope hosts, VIP
targets, and "ignore this noise" hosts. Every major commercial ASM platform
has this. Cost is low: purely additive schema + simple CLI.

**Effort:** Small. Pure SQL + argparse additions; no new dependencies.

---

## Rank 5 — Scheduled cruise daemon (`ossuary watch`)

**What:** `ossuary watch --db <db> --interval 4h` runs cruise in a loop,
writing diffs to `cruise_runs` and printing a summary each interval. Supports
`--notify slack:<webhook>` and `--notify file:<path>` for diff output. Uses
`apscheduler` (already noted as deferred from v0.1).

**Why now:** Persistent, continuous recon is the 2025 standard for bug bounty
hunters working long-running programs. Recurring state changes — ports opening
on new IPs, version bumps, service removals — are high-signal moments.
Without automation, hunters must remember to re-run cruise manually.

**Effort:** Medium. `apscheduler` adds a dependency. Daemon process management
(PID file, SIGTERM handling) adds surface area. Slack webhook integration
requires API key handling that must not land in the DB.

---

## Rank 6 — CSV / Markdown export formats for `dump`

**What:** Extend `ossuary dump` with `--format csv` (one row per service,
findings flattened as a `|`-joined column) and `--format markdown` (a GitHub
Flavored Markdown table per asset, services nested, severity-highlighted
findings). Useful for pasting into reports or bug bounty platform submissions.

**Why now:** The 2025 bug bounty workflow ends with a structured report. The
JSON dump is machine-readable but not hunter-readable. A markdown table that
can be pasted into a HackerOne or Bugcrowd submission is the last-mile piece.

**Effort:** Small. Pure string formatting; no new dependencies.

---

## Rank 7 — Scan profile presets (`--profile stealth | aggressive | web`)

**What:** Named nmap argument profiles so hunters don't need to remember flags:

- `stealth`: `-sS -T2 -Pn` (slow, SYN-only, no ping — bypasses basic IDS)
- `aggressive`: `-sV -O -T4 --script=banner` (version + OS + banners)
- `web`: `-sV -p 80,443,8080,8443,8888 -T3` (web-port-focused, medium speed)

Applied to both `discover` and `fingerprint`. Stored as `scan_profile TEXT`
in the relevant rows so cruise diffs can flag profile mismatches.

**Why now:** Solo hunters repeatedly reconstruct nmap flags from memory. A
preset system locks in tested flag combinations and makes repeatable scans
trivial. Profile storage in rows also aids audit: you know which scan produced
which service row.

**Effort:** Small. A config dict + `--profile` argparse arg per command.

---

## Not-recommended directions (and why)

| Idea | Why to skip |
|------|------------|
| Active CVE exploitation / verification | That's miasma's job — explicitly out of scope for ossuary |
| Full Nuclei template execution | ossuary is the inventory layer, not the verification layer |
| Cloud asset discovery (AWS/GCP APIs) | Different tool shape; would bloat scope significantly |
| Subdomain enumeration (subfinder/amass) | These tools are best-in-class standalone; ossuary's niche is the *local network* inventory layer, not internet-wide recon |
| PostgreSQL / MySQL backend option | The single-SQLite-file constraint is a core value proposition; don't dilute it |
| Web UI / Grafana dashboard | Out of scope for a CLI tool; adds maintenance burden |
