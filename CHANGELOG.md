# Changelog

All notable changes to ossuary are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-20

First production-ready release of ossuary — the SQLite-backed local network asset
inventory and cruise scanner for solo bug bounty hunters. Every feature shipped via
PRs #2–#36 since the v0.1 baseline (commit `d33034b`) is absorbed into this 1.0.0
entry as the shipped v1.0 surface.

### Added (asset discovery & enrichment)

- **nmap-wrapper shared library** (#2) — refactored to consume the shared `nmap-wrapper`
  package instead of an in-tree copy; one upgrade path for all necromancer tools.
- **EPSS + CISA KEV enrichment** (#fc667de) — findings now carry EPSS scores and
  KEV-listed status, surfaced via the `--kev-only` / `--min-epss` actionability filters.
- **CPE-aware OSV querying + optional NVD CVE API v2 fallback** (#7a57abf) — broader
  CPE matching with NVD fallback when OSV.dev has no record.
- **`ossuary probe` subcommand** (#fafa341) — HTTP/web layer discovery with tech
  fingerprinting; complements nmap's layer-4 service scan.
- **CVE-match integration for web_probes tech fingerprints** (#cca2a3b) — web-app
  tech signatures feed the same OSV/NVD lookup as nmap service versions.

### Added (engagement surface)

- **`ossuary tag` subcommand** (#6635e4f) — asset tagging / label system.
- **`ossuary watch` daemon** (#d7872e0) — scheduled cruise with diff summary each pass.
- **`ossuary diff` subcommand** (#04cb2a6) — finding-level diff between two engagement DBs
  (new / resolved / persisting findings). Tag-scoped via `--tag` (#81f327b).
- **`ossuary stats` subcommand** (#cbaa5ac) — engagement summary roll-up; tag-scoped
  via `--tag` (#cc9020a); actionability-filtered (#38c5476).
- **`ossuary web` subcommand** (#2ca9226) — web-layer inventory read surface.
- **Named scan profiles** (#e23b0ed) — `--profile stealth|aggressive|web` selects
  nmap flag presets; `ossuary profiles` lists them.
- **Actionability filters** (#8353db7) — `--kev-only` / `--min-epss` / `--min-severity`
  on `dump` and `stats`.
- **Priority ordering** (#cc9020a) — `--sort-by-priority` for `dump`.
- **Recency window** (#e5b7b5c) — `--since` / `--until` on `matched_at` for `dump`.
- **Age staleness** (#01b40f8) — `ossuary stale` flags findings not re-confirmed
  within N days.

### Added (export formats)

- **CSV / Markdown** (#faa128f)
- **Self-contained HTML report** (#db02b54)
- **SARIF v2.1.0** (#ebe60c0)
- **Jira CSV** (#a588184)
- **CycloneDX 1.5 SBOM** (#4711604)
- **SPDX 2.3 SBOM** (#4e22d6d)
- **OpenVEX import + extended surfaces** (#20fb92c, #4fde616)
- **Standalone OpenVEX export** (#e4a27e3)
- **CycloneDX VEX export** (#636c4ee)
- **Trivy-style text-table** (#89c5c1c)
- **Grype JSON** (#a7a6bda)
- **OWASP Dependency-Check JSON** (#27ce2b9)
- **Syft JSON** (#711bc2a)
- **Trivy JSON** (#85885f5)
- **JUnit XML** (#3912061) — CI test-results export for engagement runs.
- **`dump --limit N`** (#e306c3e) — global top-N finding cap.

### Added (enrichment)

- **Exploit-DB public-exploit enrichment** (#dc2f55b)
- **NVD CVSS v4.0 base-score enrichment** (#0483af0)

### Added (release engineering)

- **Wheel ship-gate** (#37) — `tests/test_wheel_ship_gate.py` proves the shipped wheel
  builds, installs into a fresh venv, resolves the entry-point, exposes the 17-module
  public API, and runs the read-only `ossuary profiles` smoke. The v1.0 release contract
  is regression-pinned by the ship-gate suite.
