# VulnForge Architecture

**Status:** M0–M7 implemented. M6's adapter proof uses the toy target; a real
second production target remains future work.

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
| Intelligence | Fetch/normalize CVE, GHSA, OSV, commits | M5: OSV query, raw snapshots, merge/proposal, offline mode | M5 (done) |
| Version resolver | Affected/fixed ranges, version plans | Working multi-range resolver + triage wrapper | M2/M5 (done) |
| Source analyzer | Commit diffs, affected code paths, root-cause scaffold | M5: patch capture + `root-cause.generated.md` | M5 (done) |
| Image builder | Pinned vulnerable/patched images + provenance | M2: per-version locks, base-image digest, OCI labels, image IDs | M2 (done) |
| Lab orchestrator | Build/start/stop/status, dynamic ports, isolation | M2: dynamic loopback ports, per-lab Compose project, runtime file | M2 (done) |
| PoC engine | Load, scaffold, run package probes | M3: package-local probes + `ProbeResult` | M3 (done) |
| Validator | A/B runs, repetitions, variance, verdicts | M3: medians, CV guard, hash-checked evidence | M3 (done) |
| Detector | Behavioral rules against captured telemetry | M4: offline rules + per-target `detection/evidence.json` | M4 (done) |
| Reporter | Per-CVE and global Markdown/JSON | M4: generated per-CVE/global reports from evidence | M4 (done) |
| Adapter boundary | Keep target-specific behavior out of core | M6: generalized contract + toy adapter proof | M6 (toy proof) |

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
  doctor.py         # environment checks + runtime cleanup
  __main__.py       # python -m vulnforge
  ingest/           # M5: OSV, proposal/merge, commit analysis
  triage/           # M5: resolver/prioritizer wrapper
  lab/              # M2: orchestrator, docker backend, ports, provenance
  probe/            # M3: ProbeResult, ProbeTarget, sampler, loader
  validate/         # M3: multi-run stats, verdicts, evidence bundles
  detect/           # M4: rules + offline detection runner
  report/           # M4: per-CVE/global report generation
  targets/
    base.py         # TargetAdapter protocol
    bandit/         # Bandit adapter
    toy/            # non-Bandit adapter proof
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

Current results: 116078 `CONFIRMED` (7.79 MiB vs 0.63 MiB, 3 runs);
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
| **M4** | Detection against telemetry, per-CVE/global reports | `detect` and `report` produce artifacts (done) |
| **M5** | OSV/Hex/GitHub ingestion, source analysis | Dry-run/apply, offline fixtures, commit scaffold, triage (done; full catalog flip deferred) |
| **M6** | Second target adapter | Toy target + generalized contract (done); real second target future |
| **M7** | CI, hardening, docs, optional OCI/local registry | CI, doctor, clean, docs, ruff (done); OCI/SBOM optional |

**First vertical slice:** M0–M3 for CVE-2026-116078 and CVE-2026-111101.
M4–M7 are implemented in this branch as described below.

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
- CVE-2026-116078: 100k frames, vulnerable median 7.79 MiB vs patched 0.63 MiB,
  `CONFIRMED`.
- CVE-2026-111101: corrected 1.13.1 vs 1.14.0 pair, stable 1.60x reduction,
  below the pre-registered 2.00x threshold, `INCONCLUSIVE`.

### M4 implementation notes

- `MemorySampler` records total memory, process count, top-process memory, and
  run queue; probes capture a benign connection pool for outlier baselines.
- `vulnforge.detect` evaluates the four behavioral rules offline over
  `evidence/runs` and `evidence/telemetry`.
- Rule thresholds resolve from the package's `detection/spec.json`, falling
  back to `vulnforge.detect.rules.DEFAULTS` for omitted keys.
- A signal is `TRIGGERED` only when it discriminates vulnerable from patched;
  frame-rate/body-duration rules may fire on both targets by design.
- Per-CVE `report.md`/`report.json` are generated from advisory, analysis,
  validation, detection, provenance, and evidence hashes. The global report
  reads package validation and detection evidence.
- 116078 detection: `TRIGGERED` via the memory-outlier rule.
- 111101 detection: `INCONCLUSIVE` because the rules fire on both targets.

### M5 implementation notes

- OSV ingestion writes raw snapshots, a proposed catalog, and a unified diff;
  `--apply` is explicit and merge preserves existing human metadata.
- `vulnforge analyze` captures fixing-commit patches and writes
  `analysis/root-cause.generated.md`; it does not overwrite human analysis.
- `vulnforge triage` wraps the resolver/prioritizer and can overlay packaged
  advisories onto the catalog.
- The 116078 commit review identified the real fix: `do_read_data/5` changed
  from an iolist accumulator to a binary append.
- The 111101 recorded commits are a version bump and an unrelated 2020
  refactor; the analysis flags the mismatch.
- Full catalog-to-package source-of-truth flip is deferred until all
  advisories have packages.

### M6 implementation notes

- `TargetAdapter` gained `lockfile(...)` and `version_from_stats(...)`, removing
  Bandit-specific assumptions from provenance and status reporting.
- A toy Python target (`targets/toy/`) uses one listener for app + stats and
  proves build/start/status/stop with dynamic ports.
- The core (`lab`, `probe`, `validate`, `targets/base.py`) has no Bandit
  references; a contract test enforces this.
- A real second production target (Plug/Cowboy/Nginx) remains future work.

### M7 implementation notes

- `.github/workflows/ci.yml` runs pytest, package validation, resolver drift,
  report drift, and ruff on Python 3.10–3.13; Docker integration is
  manual/weekly.
- `vulnforge doctor` checks Python, Docker, Compose, config, schemas, and
  packages.
- `vulnforge clean` removes `.vulnforge` runtime state only.
- Authoring, ingestion, verdict, and CI docs are under `docs/`.
- Optional OCI registry/SBOM/signing remains deferred.

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
| Source of truth | `data/advisories.json` remains authoritative; per-package advisory is materialized and drift-checked; full flip deferred |
| Prioritization | `data/prioritization.json` scores; weights/tiers in `config/research.yaml`; matrix drift-checked |
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

M2–M7 addressed the earlier image/lab, validation, detection, reporting,
ingestion, adapter-boundary, and CI gaps. Remaining:

1. The full catalog-to-package source-of-truth flip is deferred until all
   advisories have packages; `triage --from-packages` is an explicit overlay.
2. M6 proves the adapter boundary with a toy target, not a real second
   production target (Plug/Cowboy/Nginx).
3. Optional OCI registry, SBOM generation, and image signing are deferred.
4. The static `lab/compose.yaml` fallback duplicates the generated Compose
   intent; it remains for manual use.
5. Evidence/provenance was generated from a dirty worktree. Rebuild and
   revalidate after the M4–M7 commits if a clean `git.dirty: false` record is
   required.
6. CVE-2026-111101 remains `INCONCLUSIVE`; the metric may not capture the
   exact 1.14.0 fix, and the recorded commits do not identify it.
7. Live OSV data may not match the synthetic 2026 catalog; ingestion is
   dry-run/merge and never deletes existing advisories.
8. Detection is offline evidence review, not a live IDS or Prometheus
   integration.

These are future work, not blockers for the current factory.
