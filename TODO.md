# TODO — VulnForge

Branch: `feat/vulnforge-m3`

## M3 — probe protocol, multi-run validation, evidence (done)

- [x] Create M3 branch and baseline check
- [x] Define `ProbeResult` / `ProbeTarget` / shared probe runtime helpers
- [x] Implement package-local CVE-2026-116078 probe (HTTP/2)
- [x] Create CVE-2026-111101 package with corrected pair 1.13.1 vs 1.14.0
- [x] Implement package-local CVE-2026-111101 probe (HTTP/1)
- [x] Add runtime.json loading and target mapping
- [x] Add multi-run statistics (median/min/max/stdev/CV)
- [x] Add verdict logic: absolute + relative modes, variance/separation guard
- [x] Add evidence bundle: raw runs, telemetry, logs, image digests, hashes
- [x] Add CLI `vulnforge poc run` and `vulnforge validate`
- [x] Add pure unit tests for stats/verdict logic
- [x] Add fake-probe harness tests (no Docker)
- [x] Run gated integration for 116078 and 111101
- [x] Update package manifests/status from validation results
- [x] Update README/usage/architecture/package docs
- [x] Commit M3 and record evidence

### M3 result

| CVE | Pair | Metric | Vulnerable median | Patched median | Runs | Verdict |
|---|---|---|---:|---:|---|---|
| CVE-2026-116078 | 1.14.0 -> 1.14.1 | attack memory | 8.03 MB | 0.55 MB | 3 | CONFIRMED |
| CVE-2026-111101 | 1.13.1 -> 1.14.0 | attack memory | 2.80 MB | 1.75 MB | 3 | INCONCLUSIVE (1.60x < 2.00x) |

## M4 — detection + reports (next)

- [ ] Load package validation evidence and telemetry
- [ ] Run the four behavioral rules against captured telemetry
- [ ] Write `detection/evidence.json`
- [ ] Per-CVE report generator
- [ ] Global report aggregation from package evidence
- [ ] Add detection/evidence tests

## M5 — ingestion + source analysis

- [ ] OSV/Hex/GitHub ingestion with raw snapshots and diff/apply
- [ ] Commit diff capture and root-cause scaffold

## M6 — second target adapter

- [ ] Prove adapter boundary with a non-Bandit target

## M7 — hardening

- [ ] CI, lint/type checks, schema validation
- [ ] Optional local OCI registry / saved image bundles
