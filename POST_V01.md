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

## Rank 7 — Scan profile presets (`--profile stealth | aggressive | web`)  ✅ IMPLEMENTED

> Shipped: `ossuary.profiles` module + `--profile NAME` flag on `discover`,
> `fingerprint`, and `cruise`; new `ossuary profiles` listing command; the
> chosen profile is recorded in new `assets.scan_profile` / `services.scan_profile`
> columns (additive migration, defaults to `default`), and `cruise` reports a
> `profile_changes` section flagging services re-scanned under a different profile.

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

## Rank 8 — Actionability filters on `dump` (KEV / EPSS / severity)  ✅ IMPLEMENTED

> Shipped: `dump` gains `--kev-only`, `--min-epss P`, and `--min-severity SCORE`
> flags. Filtering happens in `dump.build_state`, so it applies uniformly to the
> json / csv / markdown formats and composes with the existing `--tag` filter.
> A finding survives only when it clears *every* threshold given; services and
> assets left with no surviving findings are pruned, so the export collapses to
> a clean list of actionable hits. With no filter flags, output is byte-for-byte
> the prior full-inventory behaviour (services with no findings still appear).
> +10 tests.

**What:** Let a hunter trim a `dump` to the findings that actually matter for a
report, using the prioritisation signal `match-cves` already records:

- `--kev-only` — only CVEs in CISA's Known Exploited Vulnerabilities catalog.
- `--min-epss P` — only findings with EPSS exploit-probability ≥ P (0–1);
  findings with no EPSS score are excluded.
- `--min-severity SCORE` — only findings whose numeric CVSS severity ≥ SCORE;
  blank / non-numeric severities are excluded.

**Why now:** This is the missing last-mile companion to Rank 1 (EPSS+KEV
enrichment) and Rank 6 (CSV/Markdown export). With NIST's enrichment retreat, a
full dump of a large engagement buries the handful of exploited / high-EPSS
CVEs under hundreds of blank-severity rows. EPSS + KEV are the live signals;
filtering on them turns the report-export from "everything" into "the part worth
submitting." Pure-Python, no new dependencies, no API keys, fully offline-tested.

**Effort:** Small. A finding-level predicate in `build_state` + three argparse
flags; the format serialisers are untouched.

---

## Rank 9 — Priority ordering for `dump` (`--sort-by-priority`)  ✅ IMPLEMENTED

> Shipped: `dump` gains `--sort-by-priority`, which reorders each service's
> findings into the same triage order `match-cves` prints — KEV-first, then
> descending EPSS, then descending numeric severity, then CVE id as a stable
> tiebreaker. Off by default (historical alphabetical-by-CVE-id ordering is
> byte-for-byte unchanged). Sorting happens in `dump.build_state`, so it applies
> uniformly to json / csv / markdown and composes with `--tag` and the R8
> actionability filters. Findings with no EPSS / blank severity sink to the
> bottom of their tier rather than being dropped. +8 tests.

**What:** The R1 enrichment and R8 filters made `dump` show the *right*
findings; this makes it show them in the *right order*. A report's most
important line should be its first, not whichever CVE id sorts earliest in the
alphabet.

**Why now:** `match-cves` already computes and prints KEV-first / EPSS-desc
ordering to the console, but the report-export artifact (`dump`) emitted findings
alphabetically — the last-mile inconsistency. With NIST's enrichment retreat the
EPSS+KEV signal is the only reliable prioritisation axis; surfacing it in the
exported order closes the loop opened by R1/R6/R8.

**Effort:** Small. A pure-Python sort key in `build_state` + one argparse flag;
the format serialisers are untouched. No new dependencies, no schema change.

---

## Rank 10 — Engagement summary command (`ossuary stats`)  ✅ IMPLEMENTED

> Shipped: new `ossuary.stats` module + `ossuary stats` subcommand with
> `--format text|json` and `--top N`. Reports engagement totals (assets /
> services / findings), the KEV count, EPSS exploit-probability tiers
> (high/medium/low/unscored), numeric-severity (CVSS) tiers
> (critical/high/medium/low/blank), and the top-N findings in the `match-cves`
> triage order (KEV-first / descending EPSS / descending severity / CVE id).
> Computed from the same assets/services/findings data `dump` reads, so the
> numbers always agree. Pure-Python, no new dependencies, no schema change, no
> network calls. +16 tests.

**What:** R1 restored the EPSS/KEV signal, R6 added report formats, R8 added
filters, and R9 added ordering — all operating on `dump`'s per-finding detail.
The missing companion is the top-of-funnel roll-up: a single at-a-glance triage
snapshot of the whole engagement, so a hunter can see "how big is this and where
is the live risk?" without scrolling a 500-row dump. `dump` answers "give me the
rows"; `stats` answers "give me the shape."

**Why now:** With NIST's enrichment retreat, raw CVSS is blank on most fresh
CVEs and the live prioritisation axis is EPSS + KEV. A per-tier count of those
signals turns a large engagement's findings into an immediately legible risk
posture — the natural front page for the report the R6/R8/R9 work produces.

**Effort:** Small. A pure-Python aggregation over the existing tables + two
argparse flags; reuses the `dump` severity-parse and priority-sort logic. No new
dependencies, no schema change, fully offline-tested.

---

## Rank 11 — Self-contained HTML report export (`dump --format html`)  ✅ IMPLEMENTED

> Shipped: `dump` gains `--format html`, a fourth export format alongside
> json / csv / markdown. It emits a single self-contained HTML document (inline
> CSS, no external assets, no JavaScript) that groups findings under each asset
> and service — the nested per-host view rather than the flat CSV/Markdown
> table. KEV findings carry a red `KEV` badge and every finding row is
> colour-coded by severity tier (critical/high/medium/low/blank, reusing the
> `stats` tiering). All cell text is HTML-escaped. Rendering happens off the
> same `dump.build_state`, so the report respects `--tag`, the R8 actionability
> filters, and R9 `--sort-by-priority` identically to the other formats. An
> empty engagement still yields a valid document with an explicit empty-state
> notice. Pure-Python (`html.escape`), no new dependencies, no schema change, no
> network calls, fully offline-tested. +8 tests.

**What:** R6 added machine- and paste-friendly export formats (csv / markdown),
and R8/R9/R10 made the export show the *right* findings, in the *right* order,
with a roll-up. The missing last-mile artifact is a **shareable, human-readable
deliverable** — a report you hand to a client or attach to an engagement
write-up without asking them to open a spreadsheet or render Markdown. A
self-contained HTML file opens in any browser, offline, with severity colour
coding and KEV badges already applied.

**Why now:** It closes the report-export lineage opened by R6. The JSON dump is
for tools, CSV is for spreadsheets, Markdown is for platform submissions — but a
formatted HTML report is the artifact a solo hunter sends as the engagement
deliverable. Reusing `build_state` means it inherits every filter and ordering
control for free, so it's a thin presentation layer over proven logic.

**Effort:** Small. A pure-Python serialiser over the existing nested state +
one `--format` choice; no new dependencies, no schema change, fully
offline-tested.

---

## Rank 12 — Tag-scoped engagement summary (`stats --tag`)  ✅ IMPLEMENTED

> Shipped: `stats` gains `--tag LABEL`, scoping the roll-up to assets carrying
> that label — the same scoping `dump --tag` (Rank 4) applies. Tag scoping
> reuses `dump.build_state(conn, tag=...)`, so the scoped totals (assets /
> services / findings / KEV / EPSS+severity tiers / top findings) agree with a
> scoped `dump` by construction. The JSON shape is unchanged (no new key); the
> text header records the scope as `engagement summary (tag: <label>)`. With no
> `--tag`, behaviour is byte-for-byte the prior whole-engagement summary. Pure
> Python, no new dependencies, no schema change, no network calls. +9 tests.

**What:** R4 added asset tagging and wired `--tag` into `dump` (export only the
in-scope / VIP / priority subset) and `cruise` (tag-change diffs). R10 added the
`stats` roll-up — but only over the *whole* engagement. The gap: a hunter who
tags hosts can scope their export but not their summary. `stats --tag` closes
that, so the summarise-then-export workflow operates on one consistent subset.

**Why now:** It's the last-mile consistency fix between the two read surfaces a
hunter uses to triage a scoped engagement. `dump --tag` answers "give me the
rows for these hosts"; `stats --tag` answers "give me the shape of these hosts."
Reusing `build_state` means the scoped numbers can't drift from a scoped dump.

**Effort:** Small. An optional `tag` param threaded through `build_stats` +
`stats` + one argparse flag; the aggregation is factored into a shared helper so
the tagged and untagged paths produce the identical structure. No new
dependencies, no schema change, fully offline-tested.

---

## Rank 13 — Actionability filters on `stats` (KEV / EPSS / severity)  ✅ IMPLEMENTED

> Shipped: `stats` gains `--kev-only`, `--min-epss P`, and `--min-severity SCORE`
> — the same actionability filters R8 added to `dump`. With any set, the roll-up
> covers only findings clearing every threshold; services / assets left with no
> surviving finding are pruned from the counts, so the summary describes exactly
> the actionable subset a filtered `dump` would export. Filtering reuses
> `dump.build_state(...)` with the identical filter params, so the filtered
> counts agree with a filtered `dump` by construction. The filters compose with
> each other and with R12's `--tag`; the text header records every active scope
> (e.g. `engagement summary (tag: in-scope, kev-only, epss>=0.5)`). The JSON
> shape is unchanged. With no tag and no filter, the whole-engagement path is
> byte-for-byte unchanged. Pure Python, no new dependencies, no schema change, no
> network calls. +14 tests.

**What:** R8 let a hunter trim a `dump` to the findings that matter; R10 added
the `stats` roll-up but only over the *whole* (or, after R12, tag-scoped)
engagement. The gap: a hunter who filters their export (`dump --kev-only
--min-epss 0.5`) had no matching summary of *that same subset*. `stats`'
actionability filters close it, so the summarise-then-export workflow operates on
one consistent subset — exactly the consistency R12 brought for `--tag`.

**Why now:** It's the last-mile consistency fix between the two read surfaces a
hunter triages a filtered engagement with. `dump --kev-only` answers "give me the
actionable rows"; `stats --kev-only` answers "give me the shape of the actionable
subset." Reusing `build_state` means the filtered numbers can't drift from a
filtered dump.

**Effort:** Small. Optional `min_epss` / `min_severity` / `kev_only` params
threaded through `build_stats` + `stats` + three argparse flags; the whole-scope
path routes through `dump.build_state` whenever a tag or filter is active, while
the unfiltered/untagged fast path is untouched. No new dependencies, no schema
change, fully offline-tested.

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
