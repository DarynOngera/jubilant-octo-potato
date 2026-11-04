# Bandit Security Research

A research + validation project for the [Bandit](https://github.com/mtrudel/bandit)
HTTP server's 24 published security advisories ([source](https://hex.pm/packages/bandit/advisories)),
built as a pipeline rather than a 24-version manual review: triage and
prioritize every advisory, then build reproducible PoCs and detection
rules for the highest-value subset.

**Status as built in this scaffold:**
- ✅ All 24 advisories normalized into `data/advisories.json`, verified against the live Hex advisory page on 2026-11-04.
- ✅ Independent Impact/Exploitability/Reachability/Detectability scoring + priority ranking (`triage/prioritizer.py`) -> `reports/technical-report.md`, `reports/vulnerability-matrix.csv`.
- ✅ Version-range resolver + lab-checkpoint planner (`triage/version_resolver.py`).
- ✅ Dockerized lab: one version-parameterized Plug/Bandit app, isolated network, resource caps (`lab/`).
- ✅ Two package-local, wire-level probes under `vulnerabilities/*/poc/`, run by the legacy harness and by `vulnforge validate`.
- ✅ Patch-verification harness with multi-run medians, variance guards, telemetry, logs, and hash-checked evidence (`vulnforge validate`).
- ✅ Behavioral detection rules implemented offline over captured evidence (`vulnforge detect`), with per-target rule verdicts and `detection/evidence.json`.
- ✅ Multi-range affected-version support, per-version CVE exposure, and deduplicated lab checkpoints (`triage/version_resolver.py`), with unit tests.
- ✅ **CVE-2026-116078 CONFIRMED**: 100k 1-byte DATA frames, vulnerable `1.14.0` median **5.27 MB**, patched `1.14.1` median **0.61 MB**, 3 runs, non-overlapping ranges; detection discriminates via the memory outlier rule.
- ✅ **VulnForge M1–M7 implemented**: package model/CLI, dynamic lab orchestrator, per-version lockfiles, digest-pinned base image, multi-run validation, offline detection, generated per-CVE/global reports, OSV ingestion with dry-run/apply, commit-diff analysis, triage, a second (toy) target adapter, doctor/clean, CI, and ruff.
- ⚠️ **CVE-2026-111101 remains `INCONCLUSIVE`.** The corrected pair is `1.13.1` vs `1.14.0` (first fixed). Three runs gave vulnerable median 2.79 MB vs patched 1.75 MB, a **1.60x** reduction, below the pre-registered 2.00x threshold. The recorded commits are a version bump and an unrelated 2020 refactor; the package is not a confirmed finding.
- ⬜ The remaining 22 advisories have priority scores and analyst notes but no package/probe yet -- Section "Extending" below is the pattern to follow.

**Live lab status (2026-11-04).** All three targets build and run under the
512 MiB cap: `4100`/`4101` = 1.13.1, `4120`/`4121` = 1.14.0, `4110`/`4111`
= 1.14.1. The image pins `ERL_AFLAGS="+Q 262144"` in both Docker stages;
without it OTP 27 sizes the fixed port table from host RAM (~1.5 GiB
reserved), and every container is OOM-killed before the app logs anything.
That same reservation previously hid PoC memory deltas inside the cap, so
the pin is required for both startup and measurement. The lab network is a
dedicated bridge but is *not* `internal: true`: on this Docker version an
internal network gets no published port mappings, so the loopback-bound
target ports are unreachable. The standalone write-up is
`reports/lab-runtime-fixes.md`.

## Why this shape

A CVSS-critical score doesn't mean a vulnerability is easy to reproduce,
and an easy-to-reproduce one isn't always high-impact. This project scores
those two things independently (see `reports/technical-report.md` Section 3)
and prioritizes research effort by a weighted combination, not by CVSS
alone.

## VulnForge factory (M1–M7)

The project is evolving from a Bandit research repo into **VulnForge**, a
local-first factory that turns an advisory into a self-contained package:
advisory, analysis, lab spec, PoC, tests, detection, evidence, and report.

```bash
.venv/bin/pip install -e '.[dev]'

vulnforge doctor
vulnforge status
vulnforge package validate

# Lab + validation + detection + reports
vulnforge lab start CVE-2026-116078
vulnforge poc run CVE-2026-116078
vulnforge validate CVE-2026-116078 --runs 3
vulnforge detect CVE-2026-116078
vulnforge report CVE-2026-116078
vulnforge lab stop CVE-2026-116078

# Intelligence + source analysis
vulnforge ingest bandit --refresh
vulnforge analyze CVE-2026-116078 --refresh
vulnforge triage
vulnforge triage --check
```

Implemented: package discovery and schema/cross-file validation, dynamic-port
lab orchestration, per-version lockfiles and digest-pinned images, provenance,
package-local probes, multi-run medians/variance guards, hash-checked evidence,
offline detection, generated per-CVE/global reports, OSV ingestion with
dry-run/apply, commit-diff root-cause scaffolding, triage, a toy second-target
adapter, doctor/clean, CI, and ruff.

Design and authoring docs:

- [`docs/vulnforge-architecture.md`](docs/vulnforge-architecture.md)
- [`docs/package-authoring.md`](docs/package-authoring.md)
- [`docs/adapter-authoring.md`](docs/adapter-authoring.md)
- [`docs/ingestion.md`](docs/ingestion.md)
- [`docs/verdicts.md`](docs/verdicts.md)
- [`docs/ci.md`](docs/ci.md)

Gated Docker integration tests:

```bash
VULNFORGE_DOCKER=1 .venv/bin/python -m unittest tests.test_lab_integration -v
VULNFORGE_DOCKER=1 .venv/bin/python -m unittest \
  tests.test_adapter_contract.ToyAdapterDockerTests -v
```

## Layout

```
data/                   advisories.json (catalog), generated matrix/checkpoints, raw snapshots
triage/                 version_resolver.py, prioritizer.py
src/vulnforge/          factory package: CLI, lab, probe, validate, detect, report, ingest, triage, doctor
vulnerabilities/        one self-contained package per CVE
schemas/                JSON Schemas for advisory/package/lab/probe/validation/detection/evidence/provenance
docs/                   architecture, package/adapter, ingestion, verdict, CI docs
lab/                    app/ (version-parameterized Plug+Bandit app), app/locks/, compose.yaml
targets/toy/            non-Bandit adapter proof target
.vulnforge/             generated per-package lab compose/runtime state (gitignored)
probes/                 legacy probes/common.py + registry.py (pre-M3 harness)
tests/regression/       legacy compare_versions.py
tests/detection/        thin self-test wrapper around vulnforge.detect.rules
tests/                  resolver, package, CLI, schema, lab, validation, detection, report, ingest, adapter tests
reports/                generate_report.py -> technical-report.md, vulnerability-matrix.csv
vulnerabilities/<CVE>/evidence/  validation + runs + telemetry + logs + hashes
config/                 research.yaml, lab-limits.yaml, vulnforge.yaml
.github/workflows/      CI: unit/schema/validation/report drift/lint + gated Docker integration
```

## Quick start

For a full command reference (including troubleshooting and extension
steps), see [`usage.md`](usage.md).

```bash
# 0. Create and activate a venv, then install the factory (editable)
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e '.[dev]'          # runtime deps + jsonschema + pytest + ruff + vulnforge CLI

# 1. Regenerate triage data (already checked in, but reproducible)
python3 triage/version_resolver.py   # both checkpoints and per-version map
python3 triage/prioritizer.py --csv reports/vulnerability-matrix.csv
python3 reports/generate_report.py
python3 tests/test_version_resolver.py
vulnforge package validate

# 2. Build and start the lab (needs Docker + network for the initial pull)
docker compose -f lab/compose.yaml build
docker compose -f lab/compose.yaml up -d
curl http://127.0.0.1:4100/healthz   # vulnerable (1.13.1)
curl http://127.0.0.1:4120/healthz   # interim (1.14.0)
curl http://127.0.0.1:4110/healthz   # patched (1.14.1)

# 3. Package lab, probe, validation, detection, report
vulnforge lab start CVE-2026-116078
python3 vulnerabilities/CVE-2026-116078/poc/exploit.py --role both
vulnforge validate CVE-2026-116078 --runs 3
vulnforge detect CVE-2026-116078
vulnforge report CVE-2026-116078
vulnforge lab stop CVE-2026-116078

# 4. Legacy single-run harness against the fixed-port lab
python3 tests/regression/compare_versions.py --cve CVE-2026-116078

# 5. Tear down the fixed-port lab
docker compose -f lab/compose.yaml down -v
```

## Isolation guarantees

Enforced in two places, not just documented:
- `probes/common.py::require_lab_target()` refuses to run against anything
  not bound to `127.0.0.1`, and hard-fails if the target name/URL contains
  `prod`/`staging`/`live`.
- `lab/compose.yaml` binds every port to `127.0.0.1` only, drops all
  capabilities, sets `read_only: true`, a 512MB/1-core/512-pid ceiling per
  container, and no restart policy (a crashed target stays crashed for
  forensics instead of silently respawning mid-experiment).
- `lab/app/Dockerfile` pins `ERL_AFLAGS="+Q 262144"` so OTP 27 does not
  reserve ~1.5 GiB for the port table from host RAM. Without it the
  containers are OOM-killed before startup, and PoC memory deltas are
  invisible inside the cap.
- `labnet` is a dedicated project bridge, but it is not `internal: true`:
  Docker will not publish loopback port mappings on an internal network.
  Add explicit firewall rules if you need a hard runtime egress block.

Full policy: `config/lab-limits.yaml`.

## Extending to the remaining advisories

1. Check `reports/technical-report.md` Section 1 for the next-highest
   `priority_P` item without a PoC, and Section 2 for whether the lab's
   `1.13.1` checkpoint is actually vulnerable to it. If it is fixed before
   1.13.1, add the matching older checkpoint image first.
2. Read its analyst note in `triage/prioritizer.py` (`SCORES[cve]["notes"]`)
   and run `vulnforge analyze <CVE> --refresh` to capture the fixing commit
   diffs and generate a root-cause scaffold. Review the diff; the recorded
   commits are not always the real fix.
3. Copy the closest existing package probe under
   `vulnerabilities/<CVE>/poc/exploit.py` as a starting point -- the
   HTTP/1 and HTTP/2 amplification probes share an in-flight
   `/admin/stats` peak-memory comparison pattern that generalizes to most
   of the resource-exhaustion family. The WebSocket family needs a
   `websocket` client (see the stub endpoint already wired in
   `lab/app/lib/lab_app/router.ex`'s `/ws/echo`); the smuggling family
   needs a second "front-end" process (e.g. a reverse proxy container) in
   front of Bandit, since smuggling impact is a property of the pair, not
   Bandit alone -- see the analyst note on CVE-2026-114216.
4. Declare the probe in `vulnerabilities/<CVE>/poc/manifest.json` with the
   correct vulnerable/patched target names, metric, and thresholds.
5. Run `vulnforge validate <CVE> --runs 3`, then `vulnforge detect <CVE>`
   and `vulnforge report <CVE>`. The global report reads package validation
   and detection evidence automatically.

## Best practices this scaffold enforces

- Advisory data is the single source of truth (`data/advisories.json`);
  the report, matrix, and lab-checkpoint plan are all *generated* from it,
  never hand-edited independently.
- CVSS is preserved verbatim and never blended into the priority score.
- Detection rules are behavioral/statistical (frame-rate-vs-payload-size,
  memory-per-connection outlier, duration-vs-size, idle process growth),
  not payload signatures, so they generalize past the exact PoC bytes.
- Affected ranges are parsed as a union, so an advisory that lists several
  ranges (backports, nested ranges) is resolved correctly rather than
  truncated to the first match.
- Each research package is schema-validated and cross-checked against the
  global catalog; `vulnforge package validate` fails on drift, missing
  artifacts, mismatched versions, or a validation status that disagrees with
  the recorded verdict.
- Validation verdicts come from repeated runs (medians, a patched-CV guard, and
  non-overlapping run ranges in absolute mode), never from a single run. The
  lab exposes a forced-GC endpoint and probes run the control first to avoid
  residual-memory bias. The validator exits non-zero for `FAIL`,
  `INCONCLUSIVE`, and `ERROR`.
- Evidence bundles include raw runs, `/admin/stats` telemetry, container logs,
  image IDs, and SHA-256 hashes; reports are generated from the bundle.
- Detection is offline rule evaluation over captured evidence, not a
  production IDS claim. It reports per-target trigger results and only calls a
  signal discriminating when it fires on vulnerable and not patched.
- Ingestion is dry-run by default: raw snapshots + proposed catalog + diff,
  with explicit `--apply`; source analysis never overwrites human-written
  root-cause notes.
- The adapter boundary is tested with a non-Bandit toy target (`targets/toy/`),
  so Bandit-specific behavior stays out of the core.
- Lab containers are disposable, capability-dropped, resource-capped, and
  loopback-only by default.
