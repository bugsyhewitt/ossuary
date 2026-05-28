# ossuary

**A SQLite-backed local network asset inventory and cruise scanner for solo bug bounty hunters.**

ossuary is the *state-tracking layer* for a bug bounty engagement. Other tools
find things; ossuary remembers them. It discovers hosts, fingerprints their
services, matches discovered versions against known CVEs, and — in **cruise
mode** — re-scans your known assets and tells you exactly what changed since
last time.

Each engagement is **one self-contained SQLite file** (`engagement-foo.db`).
Portable, single-file, no database server. No MongoDB, no Postgres — just
`sqlite3` from the Python standard library.

> ossuary is the **inventory layer**, not the verification layer. It records
> that a CVE *may* apply to a discovered version. Active exploitation /
> verification is a different tool's job.

---

## Install

```bash
pip install -e .
```

Requires **Python 3.13+**.

### System dependency: nmap

ossuary shells out to the system `nmap` binary for host discovery and service
fingerprinting, via the shared
[`nmap-wrapper`](https://github.com/bugsyhewitt/nmap-wrapper) library (installed
automatically as a dependency). You must have nmap installed:

```bash
# Debian / Ubuntu
sudo apt install nmap

# macOS
brew install nmap

# Arch
sudo pacman -S nmap
```

Verify with `nmap --version`. (The test suite mocks all nmap, OSV.dev, and NVD
calls, so tests run without nmap installed and without network access.)

---

## Commands

```
ossuary init         create the engagement DB and its tables
ossuary discover     ping/host-discover targets -> assets table
ossuary fingerprint  service/version detect known assets -> services table
ossuary probe        HTTP/web-layer probe of web ports -> web_probes table
ossuary match-cves   query OSV.dev for service versions -> findings table
ossuary cruise       re-fingerprint, diff against last saved state, report changes
ossuary watch        run cruise on an interval, emitting a diff summary each pass
ossuary dump         export the full engagement state as JSON, CSV, or Markdown
ossuary tag          attach / list / remove labels on assets for grouping & filtering
ossuary profiles     list the named scan profiles and their nmap flags
```

Run `ossuary <command> --help` for per-command flags.

### Severity enrichment (EPSS + CISA KEV)

NIST stopped enriching the large majority of new CVEs with analysed CVSS
scores, so the raw `severity` from OSV/NVD is blank or stale for most fresh
ids. To restore actionable signal, `match-cves` enriches every finding by
default:

- **EPSS** — FIRST's Exploit Prediction Scoring System probability (0–1):
  "how likely is this CVE to be exploited in the next 30 days."
- **KEV** — whether the CVE appears in CISA's
  [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  catalog, i.e. confirmed exploited in the wild.

```bash
ossuary match-cves --db engagement-acme.db
#   matched 5 finding(s) -> engagement-acme.db
#     CVE-2021-23017  severity: 7.7  EPSS: 0.87 | KEV: YES
#     CVE-2023-44487  severity: —    EPSS: 0.94 | KEV: YES
#     ...
```

The output is sorted KEV-first, then by descending EPSS, so the CVEs that are
actually being exploited float to the top regardless of CVSS.

The CISA KEV catalog (~1 MB) is downloaded once and cached in the engagement DB
with a 24-hour TTL, so repeated runs don't re-fetch it. EPSS is a per-CVE
lookup. To skip enrichment entirely (no EPSS/KEV HTTP calls), use
`--no-enrich`:

```bash
ossuary match-cves --db engagement-acme.db --no-enrich
```

### CPE-aware matching and multi-source lookup (OSV + NVD)

`fingerprint` stores nmap's CPE 2.3 URI for each service in the `services.cpe`
column (e.g. `cpe:2.3:a:apache:http_server:2.4.49:*:...`). When a CPE is
present, `match-cves` extracts the **product** field (index 4 of the CPE) and
queries OSV with that precise, vendor-normalised identifier rather than the
free-text nmap service name — so `Apache httpd` becomes `http_server`. When no
CPE is present it falls back to the nmap product name, exactly as before.

By default only OSV.dev is queried. Use `--source` to add NVD's
[CVE API v2](https://services.nvd.nist.gov/rest/json/cves/2.0) as a second
source:

```bash
# OSV only (default)
ossuary match-cves --db engagement-acme.db

# NVD only — queried by cpeName when a CPE exists, else keywordSearch
ossuary match-cves --db engagement-acme.db --source nvd

# Both — results deduplicated by CVE id (OSV wins ties, NVD fills gaps)
ossuary match-cves --db engagement-acme.db --source both
```

NVD throttles unauthenticated clients to 5 requests / 30 s; `match-cves` spaces
NVD calls ~0.6 s apart to stay under that ceiling. Supply a free
[NVD API key](https://nvd.nist.gov/developers/request-an-api-key) with
`--nvd-api-key` to raise the ceiling to 50 / 30 s (the call spacing tightens
accordingly):

```bash
ossuary match-cves --db engagement-acme.db --source both --nvd-api-key "$NVD_API_KEY"
```

Each finding's `source` column records where it came from (`osv.dev`, `nvd`, or
`osv.dev+nvd`). Why both? Given NVD's enrichment retreat the OSV+CPE path is
more reliable for non-federal CVEs, while NVD still enriches the CISA-KEV /
critical-software tier promptly — cross-referencing covers both.

### Matching web tech fingerprints (`--web`)

`ossuary probe` records each web endpoint's `Server` banner in the `web_probes`
table. Banners like `nginx/1.24.0`, `Apache/2.4.49 (Ubuntu)`, or `PHP/8.1.2`
carry a product *and* a version that nmap's layer-4 service scan often misses —
so they're a distinct CVE-matching surface. Pass `--web` to `match-cves` to
additionally feed those versioned web fingerprints through the same OSV/NVD
lookup as nmap service versions:

```bash
# 1. probe web ports first to populate web_probes
ossuary probe --db engagement-acme.db

# 2. match nmap services AND web banners against OSV
ossuary match-cves --db engagement-acme.db --web
#   matched 5 finding(s) -> engagement-acme.db
#   matched 2 web finding(s) -> engagement-acme.db
#   matched 7 finding(s) -> engagement-acme.db
```

Each `<product>/<version>` fragment in a `Server` banner is parsed (Apache is
normalised to its CPE/NVD product name `http_server`); version-less banners and
unrecognised products are ignored. Web-derived findings attach to the owning
TCP service row, so they surface in `dump` and `cruise` exactly like nmap
findings — no new table, no schema change. `--web` honours the same `--source`,
`--nvd-api-key`, and `--enrich`/`--no-enrich` options as the default scan.

Without `--web`, `match-cves` behaves exactly as before and never touches the
`web_probes` table.

### Asset tagging (`ossuary tag`)

Large engagements mean hundreds of hosts: some in scope, some out, a handful of
VIP targets, and plenty of noise to ignore. `ossuary tag` is the workflow glue
for grouping and filtering assets by **engagement, environment, scope, or
severity tier** — a free-text label layer over the assets you've discovered.

```bash
# attach a label to a discovered asset (by IP or hostname)
ossuary tag add  --db engagement-acme.db --asset 10.10.0.5 --tag in-scope
ossuary tag add  --db engagement-acme.db --asset 10.10.0.5 --tag vip
ossuary tag add  --db engagement-acme.db --asset 10.10.0.6 --tag out-of-scope

# list every tag, or filter by entity kind / single asset
ossuary tag list --db engagement-acme.db
#     10.10.0.5    in-scope
#     10.10.0.5    vip
#     10.10.0.6    out-of-scope
ossuary tag list --db engagement-acme.db --asset 10.10.0.5
ossuary tag list --db engagement-acme.db --entity asset

# remove a label
ossuary tag rm   --db engagement-acme.db --asset 10.10.0.5 --tag vip
```

Tags are free-text, so any scheme works — flat labels (`in-scope`, `noise`) or
namespaced ones (`env:prod`, `tier:critical`). Re-adding an existing tag is an
idempotent no-op, and `--asset` accepts either the asset's IP or its hostname.

Tags surface in two places automatically:

- **`dump`** carries a `tags` array on every asset, and `--tag LABEL` filters
  the export to just the assets carrying that label:

  ```bash
  # export only the in-scope hosts (and their services + findings)
  ossuary dump --db engagement-acme.db --tag in-scope > acme-in-scope.json
  ```

- **`cruise`** gains a `tag_changes` section in its diff, reporting tags added
  or removed on each asset since the previous cruise — so re-scoping decisions
  show up in the engagement's change history alongside service changes.

The tagging layer is purely additive: a single `tags` table, no change to the
four core tables. The table is entity-polymorphic (`asset` | `service` |
`finding`) so service- and finding-level tagging can be added later without a
migration; the CLI surfaces the dominant asset workflow today.

---

### Scan profiles (`--profile`)

Solo hunters keep reconstructing nmap flag combinations from memory. ossuary
ships named **scan profiles** — tested flag presets behind a memorable name —
so repeatable scans are trivial. List them with:

```bash
ossuary profiles
```

| Profile      | discover flags  | fingerprint flags                  | when to use |
|--------------|-----------------|------------------------------------|-------------|
| `default`    | `-sn`           | `-sV`                              | ossuary's original behaviour |
| `stealth`    | `-sn -T2 -Pn`   | `-sS -sV -T2 -Pn`                  | slow & quiet, evades basic IDS |
| `aggressive` | `-sn -T4`       | `-sV -O -T4 --script=banner`       | loud & thorough: OS + banners |
| `web`        | `-sn`           | `-sV -p 80,443,8080,8443,8888 -T3` | web-port-focused recon |

`discover`, `fingerprint`, and `cruise` all accept `--profile NAME` (default:
`default`, which reproduces the pre-profile flags exactly):

```bash
ossuary discover    --db engagement-acme.db --targets targets.txt --profile stealth
ossuary fingerprint --db engagement-acme.db --profile web
```

The chosen profile is recorded on each `assets.scan_profile` and
`services.scan_profile` row. Because the profile travels with the data, `cruise`
gains a `profile_changes` section: when a service is re-scanned under a different
profile than it was last fingerprinted with, the diff flags the mismatch
(`{"service": ..., "from": "default", "to": "web"}`). This is an audit aid — you
always know which flag set produced which row, and whether a re-scan changed the
methodology under your feet.

Profiles are additive: two `scan_profile TEXT` columns (defaulting to
`'default'`) migrated onto `assets` and `services`. Engagement DBs created before
profiles gain the columns automatically on the next command, with no data loss.

---

## Database schema

Four tables, one engagement file:

```
┌──────────────────────────┐
│ assets                   │  one row per discovered host
│──────────────────────────│
│ id           PK          │
│ ip           UNIQUE      │
│ hostname                 │
│ state        (up/down)   │
│ scan_profile (preset)    │  named scan profile that discovered this host
│ discovered_at            │
└────────────┬─────────────┘
             │ 1
             │
             │ N
┌────────────┴─────────────┐
│ services                 │  one row per host:port (UNIQUE asset_id,port,proto)
│──────────────────────────│
│ id           PK          │
│ asset_id     FK -> assets│
│ port                     │
│ protocol     (tcp/udp)   │
│ name / product / version │
│ cpe                      │
│ scan_profile (preset)    │  named scan profile that fingerprinted this service
│ fingerprinted_at         │
└────────────┬─────────────┘
             │ 1
             │
             │ N
┌────────────┴─────────────┐
│ findings                 │  one row per service:CVE (UNIQUE service_id,cve_id)
│──────────────────────────│
│ id           PK          │
│ service_id   FK->services│
│ cve_id / summary         │
│ severity / source        │
│ epss_score   (FIRST EPSS)│  exploit-probability float [0,1], nullable
│ kev          (0/1)       │  1 if in CISA Known Exploited Vulns catalog
│ matched_at               │
└──────────────────────────┘

┌──────────────────────────┐
│ cruise_runs              │  one row per cruise invocation
│──────────────────────────│
│ id           PK          │
│ ran_at                   │
│ snapshot     (JSON state)│  used to diff successive cruises
└──────────────────────────┘

┌──────────────────────────┐
│ kev_cache                │  cached CISA KEV catalog ids (24h TTL)
│──────────────────────────│
│ id           PK          │
│ ids          (JSON array)│  the KEV CVE-id set, fetched once per day
│ fetched_at               │  used to expire the cache
└──────────────────────────┘

┌──────────────────────────┐
│ tags                     │  free-text labels for grouping/filtering assets
│──────────────────────────│
│ id           PK          │
│ entity       (asset|...)  │  entity-polymorphic: asset / service / finding
│ entity_id                │  id of the row in that entity's table
│ tag          (label)     │  e.g. in-scope / vip / env:prod (UNIQUE per entity)
│ tagged_at                │
└──────────────────────────┘
```

Foreign keys cascade: deleting an asset removes its services and their findings.

The `epss_score` and `kev` columns are added automatically (via an idempotent
migration at startup) to engagement DBs created before enrichment landed, so
older `.db` files keep working without a manual re-init. The `tags` table and
`cruise_runs.tag_snapshot` column are added by the same migration mechanism, so
pre-tagging engagement files gain tagging support on their next `ossuary` run.

---

## Example workflow

Targets file — one IP / CIDR / hostname per line (`#` comments allowed):

```
# targets.txt
10.10.0.0/24
example.internal
```

Run the pipeline:

```bash
# 1. create the engagement database
ossuary init --db engagement-acme.db

# 2. discover live hosts
ossuary discover --db engagement-acme.db --targets targets.txt
#   -> discovered 12 live asset(s) -> engagement-acme.db

# 3. fingerprint services on every known host
ossuary fingerprint --db engagement-acme.db
#   -> fingerprinted 37 service(s) -> engagement-acme.db

# 4. match discovered service versions against OSV.dev
ossuary match-cves --db engagement-acme.db
#   -> matched 5 finding(s) -> engagement-acme.db

# 5. export the full engagement state as JSON
ossuary dump --db engagement-acme.db --format json > acme-state.json
```

### Export formats

`dump` speaks three formats via `--format`:

```bash
ossuary dump --db engagement-acme.db --format json     > acme-state.json
ossuary dump --db engagement-acme.db --format csv      > acme-findings.csv
ossuary dump --db engagement-acme.db --format markdown > acme-findings.md
```

- **`json`** (default) — the nested `assets → services → findings` structure,
  for piping into other tools.
- **`csv`** — a flat table with a header row and **one finding per row**,
  joining the asset, service, and finding columns. A service with no findings
  still emits a row (empty finding columns) so no inventory is dropped. Open it
  in a spreadsheet to sort/filter findings across the whole engagement.
- **`markdown`** — the same flat table as a GitHub-Flavoured-Markdown pipe
  table, ready to paste straight into a HackerOne / Bugcrowd submission.

All three cover the same fields; CSV and Markdown flatten the JSON nesting into
these columns: `ip, hostname, asset_state, discovered_at, tags, port, protocol,
service_name, product, version, cpe, fingerprinted_at, cve_id, summary,
severity, source, epss_score, kev, matched_at`. `--tag LABEL` filters every
format to the assets carrying that label.

### Cruise mode

Later in the engagement, re-scan and see what moved:

```bash
ossuary cruise --db engagement-acme.db
#   cruise diff: 1 added, 0 removed, 1 changed
#   {
#     "added":   [ { "service": "10.10.0.7:tcp/8443", ... } ],
#     "removed": [],
#     "changed": [ { "service": "10.10.0.5:tcp/80",
#                    "from": { "version": "1.18.0" },
#                    "to":   { "version": "1.25.0" } } ]
#   }
```

Each cruise re-fingerprints the known assets, snapshots the result into
`cruise_runs`, and diffs it against the previous snapshot. `cruise` is the
single-invocation form — run it whenever you want a delta. For unattended,
recurring deltas, use `watch` (below).

### Continuous monitoring (`ossuary watch`)

`cruise` catches what changed *since you last ran it*. On a long-running program
the high-signal moments — a port opening on a new IP, a version bump, a service
disappearing — happen between scans, and a one-shot tool only catches them if
you remember to re-run it. `ossuary watch` runs cruise on a fixed interval and
emits a diff summary each pass, turning the one-shot scan into continuous
monitoring:

```bash
# cruise every 4 hours, printing a summary each pass (Ctrl-C / SIGTERM to stop)
ossuary watch --db engagement-acme.db --interval 4h
#   watching engagement-acme.db — cruise every 14400s, until interrupted (0 notify sink(s))
#   [cruise #1 @ 2026-05-28T09:00:00] 1 added, 0 removed, 1 changed, 0 tag change(s)
#     + 10.10.0.7:tcp/8443  nginx 1.25.0
#     ~ 10.10.0.5:tcp/80  nginx 1.18.0 -> nginx 1.25.0
#   [cruise #2 @ 2026-05-28T13:00:00] 0 added, 0 removed, 0 changed, 0 tag change(s)
#     (no changes)
```

The interval accepts an integer (seconds) or a value with an `s`/`m`/`h`/`d`
suffix — `4h`, `30m`, `90s`, `1d`, or `300`. Each pass runs a full cruise
(re-fingerprint, snapshot into `cruise_runs`, diff against the previous
snapshot), so the engagement's change history is built up automatically.

**Bounded runs.** `--once` runs exactly one pass and exits; `--iterations N`
runs N passes. Both are handy for cron-driven scheduling (let cron own the
cadence, `watch --once` own the diff) or for a quick sanity check:

```bash
ossuary watch --db engagement-acme.db --once
```

**Quiet mode.** `--quiet-when-unchanged` suppresses the summary on passes where
nothing moved, so the only output you see is an actual change — ideal when
piping to a notification channel you don't want spammed.

**Notifications (`--notify`).** Push each pass's summary to a file and/or a
Slack incoming webhook. The flag is repeatable, so you can do both at once:

```bash
ossuary watch --db engagement-acme.db --interval 4h \
  --notify file:/var/log/ossuary/acme-cruise.log \
  --notify slack:https://hooks.slack.com/services/T000/B000/XXXX \
  --quiet-when-unchanged
```

- `file:<path>` appends each summary as a newline-delimited block (the parent
  directory is created if needed) — `tail -f` it or ship it downstream.
- `slack:<webhook>` POSTs each summary to a Slack incoming webhook.

Slack webhook URLs are accepted **only** on the command line and are **never**
written to the engagement DB — keep secrets out of the portable `.db` file. A
sink that fails (a down webhook, an unwritable path) is logged and skipped; one
flaky sink never kills the watch loop, and neither does a failed cruise pass —
the daemon logs the error and retries on the next interval. `watch` shuts down
cleanly on `SIGTERM`/`SIGINT`, finishing the in-flight pass's snapshot first.

> **Design note.** `watch` is a plain fixed-interval loop (stdlib `time` +
> `httpx`, both already present), not a cron-grade scheduler — a single repeating
> interval doesn't justify the extra dependency and daemon-management surface.
> Need cron-style schedules? Run `watch --once` from cron and let cron own the
> cadence.

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

The test suite is fully offline: every nmap shell-out and every OSV.dev / NVD
HTTP call is mocked, so `pytest` needs neither nmap nor network access.

---

## License

MIT — see [LICENSE](LICENSE).
