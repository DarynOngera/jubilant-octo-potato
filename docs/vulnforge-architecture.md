# VulnForge Architecture

**Status:** M0/M1 design. Bandit is the first adapter, not the product.

VulnForge turns vulnerability intelligence into executable, testable research
artifacts:

> Advisory → Analysis → Vulnerable image → PoC → Validation → Detection → Report

The product is the repeatable process and its evidence, not a library of
exploit scripts.

## 1. Principles

1. **Local-first.** No distributed workers, database, or registry until the
   local vertical slice is reliable.
2. **Human-in-the-loop.** PoC logic is researcher-authored. The factory
   scaffolds, runs, captures, validates, and reports.
3. **Separate three things.** A vulnerable image, a PoC, and detection
   evidence are independently testable artifacts.
4. **A/B by construction.** Every vulnerability claim is backed by a
   vulnerable target and a patched control with the same app and config.
5. **Evidence over assertions.** Reports are generated from recorded commands,
   metrics, logs, telemetry, and image provenance.
6. **Fail closed.** Loopback-only targets, resource caps, payload budgets, and
   explicit approval for disruptive tests.
7. **Backward compatible migration.** Existing scripts keep working through
   compatibility wrappers until the package path reaches parity.

## 2. Subsystems

| Subsystem | Responsibility | Current state | Milestone |
|---|---|---|---|
| Intelligence | Fetch/normalize CVE, GHSA, OSV, commits | Manual catalog | M5 |
| Version resolver | Affected/fixed ranges, version plans | Working multi-range resolver | M2 |
| Source analyzer | Commit diffs, affected code paths, root-cause scaffold | Commits list only | M5 |
| Image builder | Pinned vulnerable/patched images + provenance | One parameterized Bandit app | M2 |
| Lab orchestrator | Build/start/stop/status, dynamic ports, isolation | Manual Compose | M2 |
| PoC engine | Load, scaffold, run package probes | 2 scripts + central registry | M3 |
| Validator | A/B runs, repetitions, variance, verdicts | Single-run harness | M3 |
| Detector | Behavioral rules against captured telemetry | Synthetic self-test | M4 |
| Reporter | Per-CVE and global Markdown/JSON | Global report | M4 |

## 3. Repository layout

### Factory code

```text
src/vulnforge/
  cli.py            # argparse entrypoint
  config.py         # config/vulnforge.yaml
  paths.py          # workspace discovery
  models.py         # dataclasses for packages/artifacts
  schema.py         # JSON Schema validation
  packages.py       # discovery, loading, cross-file checks
  __main__.py       # python -m vulnforge
  ingest/           # M5
  triage/           # M2
  lab/              # M2
  poc/              # M3
  validate/         # M3
  detect/           # M4
  report/           # M4
  targets/
    base.py         # TargetAdapter protocol
    bandit/         # Bandit adapter
```

### Artifacts

```text
vulnerabilities/CVE-XXXX-XXXXX/
  advisory.json
  package.json
  analysis/
  lab/
  poc/
  tests/
  detection/
  evidence/
  report.md
```

### Generated / global

```text
data/               # catalog + generated indexes/exposure maps
reports/            # global report
evidence/           # cross-package raw runs
schemas/            # external JSON Schemas
config/             # factory + target + limits config
tests/              # factory tests and golden baselines
```

## 4. Core contracts

### TargetAdapter

```python
class TargetAdapter(Protocol):
    name: str
    def plan_versions(self, advisory: Advisory) -> VersionPlan: ...
    def build(self, spec: LabSpec, role: str) -> ImageRef: ...
    def start(self, spec: LabSpec) -> LabRuntime: ...
    def stop(self, lab: LabRuntime) -> None: ...
    def health(self, target: Target) -> Health: ...
    def stats(self, target: Target) -> dict: ...
```

The core must not import a target adapter directly; adapters are resolved by
config and loaded lazily.

### Probe

```python
class Probe(Protocol):
    def run(self, target: Target, **kwargs) -> ProbeResult: ...
```

`ProbeResult` carries metrics, observations, artifacts, timings, sample
counts, and errors. The M1 bridge adapts existing `run(target, **kwargs) -> dict`
probes until M3.

### VersionPlan

```json
{
  "cve": "CVE-2026-111101",
  "affected": [{"introduced": "0.1.0", "fixed": "1.14.0"}],
  "first_fixed": "1.14.0",
  "vulnerable": {"version": "1.13.1", "reason": "last vulnerable"},
  "patched": {"version": "1.14.0", "reason": "first fixed"}
}
```

Validation rejects a vulnerable version outside the affected ranges, or a
patched version that is not the first fixed release unless a rationale is
recorded.

## 5. Validation methodology

- Same app and configuration on both sides; only the target dependency version
  differs.
- Vulnerable and patched runs in the same invocation.
- Default 3 repetitions; record median, min, max, standard deviation, and
  coefficient of variation.
- Verdict from medians with a variance guard:
  - `CONFIRMED`: vulnerable median >= minimum and patched median <= maximum,
    with non-overlapping run ranges.
  - `FAIL`: patched median above maximum.
  - `INCONCLUSIVE`: vulnerable median too low, insufficient samples, or CV too
    high.
  - `ERROR`: infrastructure failure.
- Optional A/A control (same vulnerable version both sides) to catch metric
  bias.
- Correct the 111101 pair to **1.13.1 vs 1.14.0** (first fixed), not 1.14.1.
- Store raw per-run data, not only aggregates.

## 6. Evidence bundle

```text
evidence/
  execution.json       # command, environment, versions, image digests, verdict
  metrics.json         # raw samples + aggregates
  telemetry/*.jsonl    # /admin/stats time series
  logs/*.log
  detection.json
  manifest.json        # sha256 of every artifact
```

Reports are generated from the bundle. Evidence is append-only for a given
run; regenerate rather than hand-edit.

## 7. Detection methodology

- Rules operate on normalized observations, not payload signatures.
- The initial rules are the four in `tests/detection/thresholds.py`.
- M4 feeds probe observations and `/admin/stats` telemetry into the rules and
  records per-rule hits for vulnerable and patched targets.
- This is offline evidence review first; live Prometheus/proxy integration is
  deferred.

## 8. Roadmap

| Milestone | Scope | Exit criteria |
|---|---|---|
| **M0** | Architecture, schemas, golden baselines, decisions | Schemas validate current artifacts; existing commands still work |
| **M1** | Factory skeleton, package model, CLI, first package | `vulnforge package validate CVE-2026-116078` passes; old scripts work |
| **M2** | Lab orchestrator, image provenance, dynamic ports, adapters | Build/start/status works; image digests recorded; no fixed global ports |
| **M3** | Probe protocol, multi-run validation, evidence bundles | 116078 CONFIRMED over 3 runs; 111101 has a defensible verdict |
| **M4** | Detection against telemetry, per-CVE/global reports | `detect` and `report` produce artifacts |
| **M5** | OSV/Hex/GitHub ingestion, source analysis | Idempotent refresh with diff/apply; fixture tests offline |
| **M6** | Second target adapter | Same CLI works for a non-Bandit target; core has no target imports |
| **M7** | CI, hardening, docs, optional OCI/local registry | Clean-checkout CI green; Docker integration passes |

**First vertical slice:** M0–M3 for CVE-2026-116078 and CVE-2026-111101.
Roughly 6–8 focused weeks to M4; M5–M7 add another 3–4 weeks.

## 9. Non-goals for the first slice

- Autonomous exploit generation.
- PostgreSQL or any database.
- OCI registry; local images + digest metadata first.
- Prometheus; `/admin/stats` JSON first.
- Distributed workers, queues, or a web UI.
- Migrating all 24 advisories into packages at once.
- Multi-target support before the Bandit slice is solid.

## 10. Decisions

| Decision | Choice |
|---|---|
| Source of truth | `data/advisories.json` through M4; per-package advisory is materialized and drift-checked; flip in M5 |
| Package directory | `vulnerabilities/` |
| CLI | stdlib `argparse` |
| Tests | stdlib `unittest` now; pytest optional for new tests |
| Data validation | JSON Schema + `jsonschema` |
| Lab backend | subprocess `docker compose` behind a backend interface |
| Metrics source | `/admin/stats` JSON first |
| PoC generation | Researcher-authored; factory scaffolds and validates |
| Repo rename | Deferred; package/CLI first |
| 111101 pair | 1.13.1 vs 1.14.0 |

## 11. Known current gaps

1. `lab/app/mix.lock` is generated inside the image, not checked in.
2. The base image is pinned by tag, not digest.
3. Fixed ports, container names, and network names prevent parallel labs.
4. The validator runs once per target; no repetitions/variance.
5. Evidence is one JSON, not a hashed bundle.
6. Detection is synthetic, not tied to captured telemetry.
7. No ingestion or commit-level source analysis.
8. Bandit-specific assumptions are still in repo-level scripts.
9. The project needs a dedicated git history for package provenance (branch
   `feat/vulnforge-m0-m1` starts this).

These are addressed in M2–M5.
