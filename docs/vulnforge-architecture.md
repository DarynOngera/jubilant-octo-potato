# VulnForge Architecture

**Status:** M0–M3 implemented. Bandit is the first adapter, not the product.

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
| Image builder | Pinned vulnerable/patched images + provenance | M2: per-version locks, base-image digest, OCI labels, image IDs | M2 (done) |
| Lab orchestrator | Build/start/stop/status, dynamic ports, isolation | M2: dynamic loopback ports, per-lab Compose project, runtime file | M2 (done) |
| PoC engine | Load, scaffold, run package probes | M3: package-local probes + `ProbeResult` | M3 (done) |
| Validator | A/B runs, repetitions, variance, verdicts | M3: medians, CV guard, hash-checked evidence | M3 (done) |
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
  triage/           # pending: version-plan extraction
  lab/              # M2: orchestrator, docker backend, ports, provenance
  probe/            # M3: ProbeResult, ProbeTarget, sampler, loader
  validate/         # M3: multi-run stats, verdicts, evidence bundles
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
- The validator reads `.vulnforge/labs/<cve>/runtime.json`; no fixed host/port
  assumptions in package probes.
- Default 3 repetitions; record median, min, max, standard deviation, and
  coefficient of variation per target.
- Control-first probe ordering and a forced full-BEAM GC before each baseline
  (`POST /gc`) keep residual memory from inflating the control.
- Two verdict modes:
  - **absolute**: vulnerable median >= minimum, patched median <= maximum,
    patched CV <= guard, and non-overlapping run ranges.
  - **relative**: vulnerable median >= sanity floor and
    `vulnerable_median / patched_median >= min_ratio`.
- `FAIL` when the patched side is still above the maximum (or sanity cap);
  `INCONCLUSIVE` for insufficient samples, high patched CV, overlapping ranges,
  or a relative reduction below the pre-registered threshold; `ERROR` for
  probe/infrastructure failures.
- Optional A/A control runs the vulnerable target twice per repetition and
  records the ratios; it is diagnostic, not yet part of the verdict.
- Corrected 111101 pair: **1.13.1 vs 1.14.0** (first fixed), not 1.14.1.
- Store raw per-run data, telemetry, logs, image IDs, and hashes.

Current results: 116078 `CONFIRMED` (8.03 MB vs 0.55 MB, 3 runs);
111101 `INCONCLUSIVE` (1.60x relative reduction, below the 2.00x threshold).

## 6. Evidence bundle

```text
evidence/
  execution.json          # command, env, versions, image IDs, artifact hashes
  validation.json         # verdict, per-run metrics, aggregates, reason
  runs/run-NN-role.json   # raw probe result per run/role
  telemetry/run-NN-role.json  # /admin/stats time series
  logs/role.log           # container logs
  detection.json          # M4
```

`execution.json` lists every evidence artifact with a SHA-256 hash; README
files are documentation and are excluded from the hash manifest. Reports are
generated from the bundle. Evidence is append-only for a given run; regenerate
rather than hand-edit.

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
| **M3** | Probe protocol, multi-run validation, evidence bundles | 116078 CONFIRMED over 3 runs; 111101 has a defensible verdict (both done) |
| **M4** | Detection against telemetry, per-CVE/global reports | `detect` and `report` produce artifacts |
| **M5** | OSV/Hex/GitHub ingestion, source analysis | Idempotent refresh with diff/apply; fixture tests offline |
| **M6** | Second target adapter | Same CLI works for a non-Bandit target; core has no target imports |
| **M7** | CI, hardening, docs, optional OCI/local registry | Clean-checkout CI green; Docker integration passes |

**First vertical slice:** M0–M3 for CVE-2026-116078 and CVE-2026-111101.
Roughly 6–8 focused weeks to M4; M5–M7 add another 3–4 weeks.

### M2 implementation notes

- `vulnforge lab build/start/stop/status` is implemented for Bandit.
- The orchestrator allocates free loopback ports, writes a generated Compose
  file under `.vulnforge/labs/<cve>/`, and stores runtime URLs in
  `.vulnforge/labs/<cve>/runtime.json`.
- Compose project, network, containers, and image tags are namespaced per CVE,
  so multiple packages can run without fixed global ports.
- `lab/app/locks/mix-<version>.lock` pins the dependency graph per Bandit
  release; the Dockerfile selects the lock by `BANDIT_VERSION`.
- The base image is pinned by digest in both Dockerfile stages.
- `lab/provenance.json` records the Dockerfile hash, base image, lockfile
  hashes, build args, OCI labels, image IDs, git revision, and runtime targets.
- The lab adapter is resolved from `config/vulnforge.yaml` through
  `vulnforge.targets.loader`; the core does not import Bandit directly.

### M3 implementation notes

- Package probes implement `run(target, **kwargs) -> ProbeResult`; the loader
  resolves `poc/manifest.json:entrypoint`.
- Probes read the dynamic runtime, so no fixed host/port assumptions.
- The lab admin listener exposes `POST /gc`; probes run the control first and
  force GC before each baseline.
- The validator supports absolute and relative predicates, 3+ runs, a
  patched-CV guard, and non-overlapping-range checks in absolute mode.
- Evidence bundles include raw runs, telemetry, logs, image IDs, and hashes;
  the validator updates `package.json` status/verdict.
- CVE-2026-116078: 100k frames, vulnerable median 8.03 MB vs patched 0.55 MB,
  `CONFIRMED`.
- CVE-2026-111101: corrected 1.13.1 vs 1.14.0 pair, stable 1.60x reduction,
  below the pre-registered 2.00x threshold, `INCONCLUSIVE`.

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

M2 addressed the image/lab gaps, and M3 addressed the single-run validator,
package-probe bridge, and evidence-bundle gaps. Per-version lockfiles, digest
pinning, dynamic ports, package-local probes, runtime integration, multi-run
medians, telemetry, logs, and hash-checked evidence are all in place.

Remaining:

1. Detection is specified but not executed against captured telemetry (M4).
2. No ingestion or commit-level source analysis (M5).
3. Bandit-specific assumptions remain in the legacy `probes/` harness and
   `tests/regression/`; the adapter boundary is only partially extracted (M6).
4. The static `lab/compose.yaml` fallback duplicates the generated Compose
   intent; it can be removed once manual fallback is no longer needed.
5. M3 evidence/provenance was generated from a dirty worktree. Rebuild and
   revalidate after the M3 commits if a clean `git.dirty: false` record is
   required; rerunning validation may change the 111101 verdict only within
   its measurement noise.
6. CVE-2026-111101 remains `INCONCLUSIVE`; the metric may not capture the
   exact 1.14.0 fix. Commit-level review is pending.
7. No second target adapter yet (M6).

These are addressed in M4–M6.
