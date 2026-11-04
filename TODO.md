# TODO — VulnForge

Branch: `feat/vulnforge-m4-m7`

M0–M7 are implemented. This file tracks the completed work and the remaining
future items.

## M4 — detection + reports (done)

- [x] Extend telemetry with process/top-memory fields and benign-pool capture
- [x] Re-run validation to regenerate telemetry for both packages
- [x] Move/adapt detection rules into `vulnforge.detect`
- [x] Build detection runner from `evidence/runs` + `evidence/telemetry`
- [x] Extend detection schema with per-target results
- [x] Implement `vulnforge detect <CVE>` / `--all`
- [x] Implement per-CVE report generator
- [x] Implement global report generation from package evidence
- [x] Add `vulnforge report <CVE>` / `--all`
- [x] Add detection/report tests
- [x] Update docs/TODO

## M5 — ingestion + source analysis (done)

- [x] OSV source adapter with raw snapshots + hashes
- [x] Proposal/diff/apply flow (dry-run by default)
- [x] Offline fixture mode
- [x] `vulnforge ingest bandit`
- [x] Commit-diff capture + root-cause scaffold (`vulnforge analyze`)
- [x] `vulnforge triage` wrapper + packaged-advisory overlay
- [x] Ingestion/source-analysis tests
- [x] Update docs/TODO

## M6 — second target adapter (done: toy proof)

- [x] Generalize adapter/provenance/version reporting beyond Bandit
- [x] Add toy target app + adapter (`targets/toy`)
- [x] Prove build/start/status/stop on the toy target
- [x] Generalized provenance (no Bandit lockfile assumption)
- [x] Contract test: core has no Bandit imports
- [x] Gated Docker integration for the toy target
- [x] Update docs/TODO
- [ ] Real second production target (Plug/Cowboy/Nginx) — future work

## M7 — hardening, CI, docs (done)

- [x] `vulnforge doctor`
- [x] `vulnforge clean` for `.vulnforge` runtime state
- [x] CI workflow: tests, schema validation, package validate, resolver/report drift, ruff
- [x] Lint configuration + pre-commit
- [x] Adapter/package/ingestion/verdict/CI docs
- [x] Final README/usage updates
- [ ] Optional OCI registry / SBOM / signing — future work

## Current results

| CVE | Pair | Metric | Vulnerable median | Patched median | Runs | Verdict | Detection |
|---|---|---|---:|---:|---|---|---|
| CVE-2026-116078 | 1.14.0 -> 1.14.1 | attack memory | 5.03 MiB | 0.58 MiB | 3 | CONFIRMED | TRIGGERED |
| CVE-2026-111101 | 1.13.1 -> 1.14.0 | attack memory | 2.66 MiB | 1.67 MiB | 3 | INCONCLUSIVE (1.60x < 2.00x) | INCONCLUSIVE |

## Future work

- Full catalog-to-package source-of-truth flip once all 24 advisories are packaged
- Real second production target adapter
- Optional OCI registry / SBOM / image signing
- Live Prometheus/proxy detection integration
- Package the remaining 22 advisories
