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
ossuary web          list the recorded web-probe inventory (read companion to probe)
ossuary match-cves   query OSV.dev for service versions -> findings table
ossuary cruise       re-fingerprint, diff against last saved state, report changes
ossuary watch        run cruise on an interval, emitting a diff summary each pass
ossuary dump         export engagement state as JSON/CSV/Markdown/HTML/SARIF/Jira (filterable by KEV/EPSS/severity)
ossuary stats        print an at-a-glance engagement summary (counts + top hits)
ossuary stale        flag findings not re-confirmed within N days (age staleness)
ossuary diff         compare two engagement DBs -> new / resolved / persisting findings
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
- **Exploit** — whether a public exploit / PoC for the CVE is catalogued in
  [Exploit-DB](https://www.exploit-db.com/), i.e. a ready-to-run exploit already
  exists. This is a distinct axis from KEV: a fresh CVE with a published exploit
  but no in-the-wild sightings (and a low EPSS) only shows up on this signal.

```bash
ossuary match-cves --db engagement-acme.db
#   matched 5 finding(s) -> engagement-acme.db
#     CVE-2021-23017  severity: 7.7  EPSS: 0.87 | KEV: YES | Exploit: YES
#     CVE-2023-44487  severity: —    EPSS: 0.94 | KEV: YES | Exploit: no
#     ...
```

The output is sorted KEV-first, then by descending EPSS, so the CVEs that are
actually being exploited float to the top regardless of CVSS.

The CISA KEV catalog (~1 MB) and the Exploit-DB index are each downloaded once
and cached in the engagement DB (`kev_cache` / `exploitdb_cache`) with a 24-hour
TTL, so repeated runs don't re-fetch them. EPSS is a per-CVE lookup. To skip
enrichment entirely (no EPSS/KEV/Exploit-DB HTTP calls), use `--no-enrich`:

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

When NVD supplies a CVSS base score, ossuary takes it newest-standard-first:
**CVSS 4.0 → 3.1 → 3.0 → 2.0**. As CNAs and NVD adopt CVSS 4.0, a growing share
of freshly analysed CVEs are scored *only* under v4, so consulting `cvssMetricV40`
first means those CVEs populate a finding's `severity` (and flow through the
`--min-severity` filters and priority sort) instead of falling through to blank.

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

### Reviewing the web layer (`ossuary web`)

`ossuary probe` *writes* the web layer (status codes, `Server` banners, page
titles, redirect chains, and tech fingerprints) into the `web_probes` table, but
its live stdout summary scrolls past once. `ossuary web` is the *read* companion:
it lists the persisted web inventory at any time after probing — the same way
`stats` / `stale` read what `match-cves` wrote.

```bash
# review every recorded web endpoint, grouped per host
ossuary web --db engagement-acme.db
#   web inventory
#     count: 2
#     https://10.0.0.5:443  [200]
#       hostname: portal.acme
#       server: nginx/1.24.0
#       title: Acme Portal
#       tech: nginx, wordpress
#     http://10.0.0.5:80  [301]
#       redirects: https://portal.acme/
```

Two filters scope the listing without re-probing:

```bash
# only one host's web surface
ossuary web --db engagement-acme.db --host portal.acme

# only endpoints running a given technology (case-insensitive substring)
ossuary web --db engagement-acme.db --tech wordpress

# machine-readable, for piping into other tooling (filters compose)
ossuary web --db engagement-acme.db --tech nginx --format json
```

`--format json` emits the same rows as a structured array, with `redirect_chain`
and `tech_fingerprints` decoded back into lists. No network, no schema change —
it reads only what `probe` already stored.

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

Tags surface in three places automatically:

- **`dump`** carries a `tags` array on every asset, and `--tag LABEL` filters
  the export to just the assets carrying that label:

  ```bash
  # export only the in-scope hosts (and their services + findings)
  ossuary dump --db engagement-acme.db --tag in-scope > acme-in-scope.json
  ```

- **`stats`** accepts the same `--tag LABEL`, scoping the engagement roll-up to
  the tagged subset — so you can summarise and export the identical set:

  ```bash
  # roll up only the in-scope hosts
  ossuary stats --db engagement-acme.db --tag in-scope
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
│ exploit      (0/1)       │  1 if a public exploit exists in Exploit-DB
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

The `epss_score`, `kev` and `exploit` columns are added automatically (via an
idempotent migration at startup) to engagement DBs created before each
enrichment landed, so older `.db` files keep working without a manual re-init.
The `tags` table and
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

`dump` speaks six formats via `--format`:

```bash
ossuary dump --db engagement-acme.db --format json     > acme-state.json
ossuary dump --db engagement-acme.db --format csv      > acme-findings.csv
ossuary dump --db engagement-acme.db --format markdown > acme-findings.md
ossuary dump --db engagement-acme.db --format html     > acme-report.html
ossuary dump --db engagement-acme.db --format sarif    > acme-findings.sarif
ossuary dump --db engagement-acme.db --format jira     > acme-tickets.csv
```

- **`json`** (default) — the nested `assets → services → findings` structure,
  for piping into other tools.
- **`csv`** — a flat table with a header row and **one finding per row**,
  joining the asset, service, and finding columns. A service with no findings
  still emits a row (empty finding columns) so no inventory is dropped. Open it
  in a spreadsheet to sort/filter findings across the whole engagement.
- **`markdown`** — the same flat table as a GitHub-Flavoured-Markdown pipe
  table, ready to paste straight into a HackerOne / Bugcrowd submission.
- **`html`** — a single **self-contained HTML report** (inline CSS, no external
  assets, no JavaScript) grouping findings under each asset and service, with a
  red **KEV** badge on confirmed-exploited CVEs and severity-tier colour coding
  on every finding row. It renders offline and is safe to hand to a client as a
  deliverable — open it in a browser or attach it to an engagement write-up.
- **`sarif`** — a **SARIF v2.1.0** document (Static Analysis Results Interchange
  Format, the OASIS standard). One `result` per finding, one `rule` per distinct
  CVE, located by `host:proto/port`. EPSS, KEV, severity, product and version
  ride along as result `properties`. This is the artifact GitHub code scanning,
  DefectDojo, Azure DevOps, and the wider security-tooling ecosystem ingest
  natively, so you can pipe an engagement's findings straight into a triage
  pipeline or a code-scanning dashboard.
- **`jira`** — an **issue-tracker import CSV** shaped as tickets rather than raw
  inventory: one row per finding with `Summary`, `Description`, `Priority`, and
  `Labels` columns (plus `Component`, `CVE`, `EPSS`, `KEV`, `Severity`, `Host`,
  `Port` for context). Both Jira's CSV importer and Linear's CSV importer map
  those leading columns straight onto issue fields, so a hunter turns an
  engagement's findings into a triage backlog without retyping. `Priority` is
  mapped from the live signal — a **KEV** (confirmed-exploited) finding is always
  `Highest`, then the hotter of EPSS / CVSS drives it (`>= 0.5` EPSS or `>= 7.0`
  CVSS → `High`, `>= 0.1` EPSS or `>= 4.0` CVSS → `Medium`, otherwise `Low`).
  Each row's `Labels` carries the host's tags plus `kev` when confirmed
  exploited. Like SARIF it is finding-centric (a service with no finding produces
  no ticket).

The `json`, `csv`, and `markdown` formats cover the same fields; CSV and
Markdown flatten the JSON nesting into these columns: `ip, hostname,
asset_state, discovered_at, tags, port, protocol, service_name, product,
version, cpe, fingerprinted_at, cve_id, summary, severity, source, epss_score,
kev, exploit, matched_at`. The `html` report carries the same underlying data, presented
per-host rather than as a flat table. The `sarif` document is finding-centric —
a service with no finding produces no `result` — and maps each finding to a SARIF
`level`: a **KEV** finding is always `error` (regardless of the often-blank
post-NIST-retreat CVSS), then numeric severity drives it (`>= 7.0` → `error`,
`>= 4.0` → `warning`, lower → `note`), with an un-scored, non-KEV finding
defaulting to `warning`. The `jira` CSV is likewise finding-centric (one ticket
per finding, no row for a finding-less service) and uses *issue-tracker* column
names (`Summary` / `Description` / `Priority` / `Labels` …) rather than the raw
inventory columns the plain `csv` format emits. `--tag LABEL` filters every
format to the assets carrying that label (for `jira`, the tags also flow into
each ticket's `Labels`).

#### Actionability filters — `--kev-only`, `--min-epss`, `--min-severity`

NIST's 2026 enrichment retreat left raw CVSS `severity` blank on most fresh
CVEs, so a full `dump` of a large engagement buries the few findings that matter
under the noise. The live prioritisation signal lives in the EPSS exploit
probability and CISA KEV status that `match-cves` already records — these three
flags trim the export to just the findings worth writing up in a report:

```bash
# only CVEs CISA has confirmed exploited in the wild
ossuary dump --db engagement-acme.db --format markdown --kev-only

# only CVEs with >= 50% exploit probability in the next 30 days (EPSS)
ossuary dump --db engagement-acme.db --format markdown --min-epss 0.5

# only CVEs with a numeric CVSS severity >= 7.0
ossuary dump --db engagement-acme.db --format csv --min-severity 7.0
```

Semantics:

- `--kev-only` keeps findings where `kev = 1`.
- `--min-epss P` keeps findings whose EPSS score is present **and** `>= P`;
  a finding with no EPSS score is dropped once an EPSS floor is set.
- `--min-severity SCORE` keeps findings whose `severity` parses as a number
  **and** is `>= SCORE`; blank / non-numeric severities are dropped once a
  severity floor is set.

The flags **compose** (a finding must clear every threshold given) and combine
with `--tag` (e.g. `--tag in-scope --kev-only`). They apply identically to
`json`, `csv`, `markdown`, `html`, `sarif`, and `jira`. When a filter is active, services and assets left
with no surviving findings are pruned, so the output collapses to a clean list
of actionable hits. With no filter flags, `dump` returns the full inventory
exactly as before (services with no findings still appear).

#### Priority ordering — `--sort-by-priority`

The actionability filters decide *which* findings make the report; the order
they appear in still matters when you're writing it up. By default `dump` emits
each service's findings alphabetically by CVE id — which buries the exploited
CVEs among the cold ones. `--sort-by-priority` reorders each service's findings
into the same triage order `match-cves` prints to the console: **KEV-first,
then descending EPSS, then descending numeric severity**, with CVE id as a
deterministic final tiebreaker. The findings actually being exploited lead every
service in the report:

```bash
# the report, highest-signal findings first
ossuary dump --db engagement-acme.db --format markdown --sort-by-priority

# combine with filters: only the KEV hits, hottest first
ossuary dump --db engagement-acme.db --kev-only --sort-by-priority
```

Findings with no EPSS score or a blank/non-numeric severity sink to the bottom
of their tier rather than being dropped (use the filters above to drop them).
The flag applies identically to `json`, `csv`, `markdown`, `html`, `sarif`, and `jira`, and composes with
`--tag` and the actionability filters. Without it, ordering is the historical
alphabetical-by-CVE-id, byte-for-byte unchanged.

#### Recency window — `--since`, `--until`

`cruise` (and the `watch` daemon looping it) re-scan the same engagement over
time, so a finding's `matched_at` timestamp records *when* it was recorded.
`--since DATE` and `--until DATE` trim the export to the findings recorded inside
a window — the slice for "what's new since my last pass" rather than the whole
history. Both bounds are **inclusive**, and either may be given alone (open-ended
on the other side):

```bash
# only the findings recorded on or after a date (e.g. since the last cruise)
ossuary dump --db engagement-acme.db --since 2026-05-01

# only the findings recorded up to and including a date
ossuary dump --db engagement-acme.db --until 2026-05-29

# bound a window: findings recorded in May 2026
ossuary dump --db engagement-acme.db --since 2026-05-01 --until 2026-05-31
```

Dates may be a bare `YYYY-MM-DD` or a full `'YYYY-MM-DD HH:MM:SS'`. A bare-date
`--until` covers the **whole** day (a finding matched at `2026-05-29 14:30:00`
survives `--until 2026-05-29`). A finding with no recorded `matched_at` is
excluded once either bound is set, and services / assets left with no surviving
findings are pruned — exactly like the actionability filters. The window applies
identically to `json`, `csv`, `markdown`, `html`, `sarif`, and `jira`, and composes with
`--tag`, the actionability filters, and `--sort-by-priority`. With neither bound
set, the export is unchanged.

#### VEX suppression — `--vex`

After a `match-cves` pass a large engagement carries hundreds of CVE findings,
and triage inevitably rules a chunk of them *not actually exploitable here* — a
false-positive version match, a disabled feature, a box patched out-of-band.
Re-scanning re-discovers those same CVEs every time, so the noise comes back on
every cruise unless you record "already ruled out." A
[VEX document](https://github.com/openvex/spec) (Vulnerability Exploitability
eXchange — the open **OpenVEX** JSON shape) is the portable, standard way to
capture those rulings, and `--vex` feeds one into the export to **suppress** the
ruled-out findings — hiding them from every report without deleting the rows
(the evidence stays in the DB).

```bash
# hide every finding the VEX has cleared (not_affected / fixed)
ossuary dump --db engagement-acme.db --vex triage.openvex.json --format markdown
```

A VEX document is a list of `statements`, each naming a `vulnerability` (the
CVE), a `status`, and optionally the `products` it applies to:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "author": "you",
  "statements": [
    { "vulnerability": { "name": "CVE-2024-1111" }, "status": "not_affected" },
    { "vulnerability": { "name": "CVE-2024-2222" }, "status": "fixed",
      "products": [ { "@id": "10.10.0.5:tcp/443" } ] }
  ]
}
```

Suppression semantics:

- A finding is suppressed only when its CVE is ruled **`not_affected`** or
  **`fixed`** — the two statuses that mean "not a live issue here." `affected`
  and `under_investigation` leave the finding visible (they are not a clearance).
- A statement with **no `products`** is a *blanket* ruling — the CVE is hidden
  wherever it appears.
- A statement that **lists `products`** is a *scoped* ruling — the CVE is hidden
  only on findings whose location matches a listed product identifier. ossuary
  matches a finding against its asset ip, its `ip:proto/port` service location,
  and its service CPE, so you can clear a CVE on one host without silencing the
  same CVE on another.

Suppression composes with `--tag`, the actionability filters, `--since/--until`,
and `--sort-by-priority`, and applies identically to `json`, `csv`, `markdown`,
`html`, `sarif`, and `jira`; services / assets left with no surviving finding are
pruned. With no `--vex`, the export is unchanged. A missing or malformed VEX file
fails loudly with a clear error.

### Engagement summary (`ossuary stats`)

`dump` emits the full per-finding inventory; `stats` gives the top-of-funnel
view — a single at-a-glance triage snapshot answering "how big is this
engagement and where's the live risk?" without scrolling a 500-row dump. It is
computed from the same `assets` / `services` / `findings` data, so the numbers
always agree with `dump`. No network calls, no schema change.

```bash
ossuary stats --db engagement-acme.db
```

```
engagement summary
  assets:   1
  services: 1
  findings: 2
  KEV (actively exploited): 1
  EPSS tiers:
    high (>=0.50):   1
    medium (>=0.10): 0
    low (<0.10):     1
    unscored:        0
  severity tiers:
    critical (>=9.0): 1
    high (>=7.0):     0
    medium (>=4.0):   0
    low (<4.0):       1
    blank:            0
  top 2 finding(s) by priority:
    CVE-HOT  severity: 9.8  EPSS: 0.94 | KEV: YES
    CVE-COLD  severity: 3.1  EPSS: 0.02 | KEV: no
```

The breakdowns use the live prioritisation signal restored by `match-cves`
enrichment: **KEV** (CISA Known Exploited Vulnerabilities — confirmed
exploited), **EPSS** tiers (exploit probability), and numeric-**severity**
(CVSS) tiers, with un-enriched findings counted in their `unscored` / `blank`
buckets. The `top findings` list is ordered KEV-first / descending-EPSS /
descending-severity / CVE-id — the same triage order `dump --sort-by-priority`
and `match-cves` use.

```bash
# the same numbers as JSON, for piping into other tools
ossuary stats --db engagement-acme.db --format json

# show the top 20 hits (or 0 to omit the list entirely)
ossuary stats --db engagement-acme.db --top 20
```

`--tag LABEL` scopes the roll-up to assets carrying that tag — the same
scoping `dump --tag` applies (see [Asset tagging](#asset-tagging-ossuary-tag)).
This is the workflow companion to a scoped export: summarise *and* dump the
exact same in-scope / VIP / priority subset. The scoped counts agree with a
scoped `dump` by construction, and the text header records the scope.

```bash
# summarise only the hosts tagged "in-scope"
ossuary stats --db engagement-acme.db --tag in-scope
```

```
engagement summary (tag: in-scope)
  assets:   1
  ...
```

`stats` also accepts the same actionability filters as `dump` — `--kev-only`,
`--min-epss P`, and `--min-severity SCORE` (see
[Actionability filters](#actionability-filters----kev-only---min-epss---min-severity)).
With any set, the roll-up describes only the findings worth reporting:
non-clearing findings are dropped, and services / assets left with no surviving
finding are pruned from the counts — so the summary matches what a filtered
`dump` would export, by construction. The filters compose with each other and
with `--tag`, and the text header records every active scope.

```bash
# summarise only the actively-exploited, high-EPSS findings
ossuary stats --db engagement-acme.db --kev-only --min-epss 0.5
```

```
engagement summary (kev-only, epss>=0.5)
  assets:   1
  services: 1
  findings: 1
  ...
```

This is the roll-up companion to the filtered export: `dump --kev-only` gives
you *the actionable rows*, `stats --kev-only` gives you *the shape of the
actionable subset* — both over the identical set of findings.

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

### Finding-level diff (`ossuary diff`)

`cruise` and `watch` diff the *service* surface of one DB over time — ports,
versions, services appearing and disappearing. They never answer the question a
hunter actually asks after re-scanning: **which CVE findings are new, and which
got resolved (patched)?** `ossuary diff` compares the findings of two engagement
DB files — a **baseline** (the earlier scan) and a **current** one (the later
scan) — and classifies every finding:

| class | meaning |
|---|---|
| `new` | in current, not in baseline — **newly exposed** |
| `resolved` | in baseline, not in current — **patched / removed** |
| `persisting` | in both — still exposed |

A finding's identity is the triple `(ip, protocol/port, cve_id)` — the same
host:service location the SARIF / HTML exports use — so the same CVE on two hosts
is two findings, and a CVE that moves ports reads as one `resolved` + one `new`
(it genuinely moved).

The usual workflow is to keep a dated copy of the baseline DB, run a fresh scan
into a new DB, then diff:

```bash
# baseline.db was last week's scan; engagement-acme.db is today's
ossuary diff --db baseline.db --against engagement-acme.db
#   finding diff: 1 new, 1 resolved, 2 persisting
#   new (1) — newly exposed:
#     10.10.0.5:tcp/80 (nginx 1.24.0)  CVE-2025-9999  severity: 8.8  EPSS: 0.90 | KEV: YES
#   resolved (1) — patched / removed:
#     10.10.0.5:tcp/80 (nginx 1.18.0)  CVE-2024-1234  severity: 9.1  EPSS: 0.80 | KEV: YES
```

`--db` is the baseline, `--against` is the current scan. The text report lists
the `new` and `resolved` findings (the two that demand attention) and counts the
`persisting` ones without listing them — a plain `dump` already covers unchanged
exposure. `--format json` emits the full `{new, resolved, persisting}` structure
for piping.

`new`/`persisting` entries carry the **current** DB's finding detail (severity /
EPSS / KEV / summary); `resolved` entries carry the **baseline**'s (the current
DB no longer holds them).

**Tag scoping.** `diff` accepts the same `--tag LABEL` as `dump` / `stats` /
`stale`, scoping the comparison to assets carrying that label — so you can diff
just your in-scope (or VIP / priority) hosts instead of the whole engagement:

```bash
# only diff the hosts tagged "in-scope" on each side
ossuary diff --db baseline.db --against engagement-acme.db --tag in-scope
```

`--tag` scopes **each side independently**, using the tags recorded *in that
DB* — exactly how `dump --tag` scopes a single DB. So a host tagged `in-scope`
in the current scan but not (yet) in the baseline is scoped per-DB, and a tag no
asset carries scopes both sides to nothing (an empty diff). This is the diff
companion to a tagged export: `dump --tag in-scope` gives you the in-scope rows,
`diff --tag in-scope` gives you what changed among them.

**Actionability filters.** `diff` accepts the same `--kev-only`, `--min-epss`,
and `--min-severity` filters as `dump` and `stats`. They scope *both* sides
before diffing, so you can ask "what's new among the findings worth reporting":

```bash
# only diff the KEV (actively-exploited) findings
ossuary diff --db baseline.db --against engagement-acme.db --kev-only

# only the high-EPSS exposure that changed
ossuary diff --db baseline.db --against engagement-acme.db --min-epss 0.5 --format json

# compose: what's new among the in-scope, actively-exploited findings
ossuary diff --db baseline.db --against engagement-acme.db --tag in-scope --kev-only
```

> **Design note.** `diff` reads each DB through the same `build_state` the
> exports use, so the tag-scoped / filtered, location-keyed view it diffs is
> identical to what a tag-scoped / filtered `dump` of each DB would show. Pure
> Python, no new schema, no network.

### Age staleness (`ossuary stale`)

`dump --since/--until` slices findings by an *absolute* scan-time window. `stale`
asks the *relative* question: **which findings haven't been re-confirmed by a
recent scan?** Every time `match-cves` re-matches a CVE on a service it refreshes
that finding's `matched_at`, so a finding whose `matched_at` has gone cold has not
been re-seen since that date. Two things produce a cold finding, and both are
worth surfacing:

- the service was **patched or removed** and the stale row is now noise to prune;
- it's a **long-standing exposure** that has sat unresolved for weeks.

`ossuary stale` flags every finding older than a threshold (default **30 days**),
ordered oldest-first so the most-neglected finding leads:

```bash
ossuary stale --db engagement-acme.db
#   stale findings (> 30 days, as of 2026-05-29 12:00:00)
#     count: 1
#     10.10.0.5:tcp/80  CVE-2020-1234  age: 148.3d  severity: 9.0  EPSS: 0.80 | KEV: YES  (last seen: 2026-01-01 12:00:00)

# tighten or loosen the window
ossuary stale --db engagement-acme.db --max-age-days 7
```

A finding with **no recorded `matched_at`** is always flagged (unknown age == not
recently confirmed), with its age reported as `unknown`; these sort last.

**Scoping & filters.** `stale` accepts the same `--tag`, `--kev-only`,
`--min-epss`, and `--min-severity` controls as `dump` / `stats` / `diff`, so you
can narrow the candidate set before applying the age threshold — e.g. "which of
my actively-exploited findings have gone stale":

```bash
ossuary stale --db engagement-acme.db --kev-only
ossuary stale --db engagement-acme.db --tag in-scope --min-epss 0.5 --format json
```

`--format json` emits `{max_age_days, as_of, count, stale[]}` for piping.

> **Design note.** `stale` reads through the same `build_state` the exports use,
> so its scoped/filtered candidate set is identical to what a filtered `dump`
> would show; the age comparison then applies on top. Pure Python, no new schema,
> no network calls.

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
