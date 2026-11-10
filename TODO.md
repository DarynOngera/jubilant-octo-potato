# TODO — VulnForge

Branch: `docs/trim-readme`

M0–M7 are implemented. This file tracks the completed work and the remaining
future items.

## Prioritizer data-driven (done)

- [x] Move per-CVE I/E/R/D/notes into `data/prioritization.json`
- [x] Read weights and tier thresholds/labels from `config/research.yaml`
- [x] Add `schemas/prioritization.schema.json`
- [x] Validate completeness, unknown CVEs, weights, tiers
- [x] Deterministic matrix sort with CVE tie-break
- [x] Extend `vulnforge triage --check` to include matrix drift
- [x] Add prioritizer/data/package-consistency tests
- [x] Update report/docs to point at data/config instead of code

## M4 — detection + reports (done)

- [x] Extend telemetry with process/top-memory fields and benign-pool capture
- [x] Re-run validation to regenerate telemetry for both packages
- [x] Move/adapt detection rules into `vulnforge.detect`
- [x] Build detection runner from `evidence/runs` + `evidence/telemetry`
- [x] Resolve detection thresholds from each package's `detection/spec.json`
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

## M8 — local UI (done)

- [x] Stdlib loopback server (`vulnforge ui`) with no new dependencies
- [x] Read model over packages, validation, detection, provenance, and matrix
- [x] Overview, CVE detail, labs, matrix, activity, and health pages
- [x] Vendored offline Markdown rendering with downloadable reports
- [x] Allowlisted job runner for lab/validation/detection/report actions
- [x] CSRF, loopback Host/Origin checks, and action validation
- [x] UI tests and docs

## CVE-driven PoC engine

- [x] `vulnforge poc build <CVE>` with reviewed profile selection
- [x] HTTP/2 one-byte DATA-frame and HTTP/1 one-byte chunk profiles
- [x] HTTP/1 chunked length-cap profile (`CVE-2026-39803`)
- [x] Provenance marker, idempotent rebuilds, `--force`, hand-authored protection
- [x] `poc/proposal.json` with advisory facts, predicate, and provenance
- [x] Patch-signal extraction, selector confidence, and contradiction veto
- [x] Producer commands (`validate`, `detect`, `report`) can finish a bundle
- [ ] Duration-based oracle for `CVE-2026-105659` (HTTP/2 blocked-send deadline)
- [ ] Bounded parameter search (Phase 3)
- [ ] Minimization (Phase 4)

## Current results

| CVE | Pair | Metric | Vulnerable median | Patched median | Runs | Verdict | Detection |
|---|---|---|---:|---:|---|---|---|
| CVE-2026-116078 | 1.14.0 -> 1.14.1 | attack memory | 7.78 MiB | 0.60 MiB | 3 | CONFIRMED | TRIGGERED |
| CVE-2026-111101 | 1.13.1 -> 1.14.0 | attack memory | 2.66 MiB | 1.67 MiB | 3 | INCONCLUSIVE (1.60x < 2.00x) | INCONCLUSIVE |
| CVE-2026-39803 | 1.11.0 -> 1.11.1 | attack memory | 8.33 MiB | 0.96 MiB | 3 | CONFIRMED | TRIGGERED |

## Future work

- Full catalog-to-package source-of-truth flip once all 24 advisories are packaged
- Real second production target adapter
- Optional OCI registry / SBOM / image signing
- Live Prometheus/proxy detection integration
- Package the remaining 22 advisories
