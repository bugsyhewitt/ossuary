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
ossuary dump         export the full engagement state as JSON
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
```

Foreign keys cascade: deleting an asset removes its services and their findings.

The `epss_score` and `kev` columns are added automatically (via an idempotent
migration at startup) to engagement DBs created before enrichment landed, so
older `.db` files keep working without a manual re-init.

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
`cruise_runs`, and diffs it against the previous snapshot. In v0.1 this is a
single-invocation diff — run it whenever you want a delta. (A long-running
scheduled daemon is deferred to a later release.)

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
