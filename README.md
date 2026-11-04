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
- ✅ Two implemented, wire-level PoCs for the top-ranked findings (`probes/http1`, `probes/http2`), registered once in `probes/registry.py`.
- ✅ Patch-verification harness that runs a PoC against its correct vulnerable + patched target pair and asserts the effect collapses (`tests/regression/compare_versions.py`).
- ✅ Behavioral detection rules, self-tested against synthetic data (`tests/detection/thresholds.py`).
- ✅ Multi-range affected-version support, per-version CVE exposure, and deduplicated lab checkpoints (`triage/version_resolver.py`), with unit tests.
- ✅ **CVE-2026-116078 validated live** on 2026-11-04: interim `1.14.0` amplified **8.90x**, patched `1.14.1` **0.58x** -> `CONFIRMED`.
- ✅ **VulnForge M1/M2 skeleton**: `src/vulnforge/` package + CLI, JSON Schemas, package loader/validator, dynamic-port lab orchestrator, per-version lockfiles, digest-pinned base image, and the first self-contained package at `vulnerabilities/CVE-2026-116078/`.
- ⚠️ **CVE-2026-111101 remains `INCONCLUSIVE`.** The probe runs, but both `1.13.1` and `1.14.1` show large per-chunk memory growth against the large-chunk control (at 20k chunks, ~4.2 MB vs ~2.2 MB), so the current metric does not isolate the fix. It is registered but must not be cited as a confirmed finding until the probe is redesigned.
- ⬜ The remaining 22 advisories have priority scores and analyst notes but no PoC yet -- Section "Extending" below is the pattern to follow.

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

## VulnForge factory (M1/M2)

The project is evolving from a Bandit research repo into **VulnForge**, a
local-first factory that turns an advisory into a self-contained package:
advisory, analysis, lab spec, PoC, tests, detection spec, evidence, and report.

The M1/M2 skeleton is usable now:

```bash
.venv/bin/pip install -e '.[dev]'

vulnforge status
vulnforge package list
vulnforge package show CVE-2026-116078
vulnforge package validate CVE-2026-116078

vulnforge lab build CVE-2026-116078
vulnforge lab start CVE-2026-116078
vulnforge lab status CVE-2026-116078
vulnforge lab stop CVE-2026-116078
```

Implemented: package discovery, JSON Schema validation, cross-file consistency
checks, advisory-to-catalog drift detection, the dynamic-port lab orchestrator,
per-version lockfiles, digest-pinned base image, and image/build provenance.

Planned and exposed as explicit stubs: `triage` (M2 version-plan extraction),
`poc`/`validate` (M3), `detect`/`report` (M4), `ingest` (M5). The full design is
in [`docs/vulnforge-architecture.md`](docs/vulnforge-architecture.md).

The M2 lab lifecycle has a gated integration test:

```bash
VULNFORGE_DOCKER=1 .venv/bin/python -m unittest tests.test_lab_integration -v
```

## Layout

```
data/                   advisories.json (source of truth), generated matrix/checkpoints
triage/                 version_resolver.py, prioritizer.py
src/vulnforge/          factory package: CLI, config, models, schemas, package validation
vulnerabilities/        one self-contained package per CVE
schemas/                JSON Schemas for advisory/package/lab/probe/validation/detection/evidence
docs/                   architecture and authoring docs
lab/                    app/ (version-parameterized Plug+Bandit app), app/locks/, compose.yaml
.vulnforge/             generated per-package lab compose/runtime state (gitignored)
probes/                 common.py (guardrails + memory sampler), registry.py (single PoC registry), http1/, http2/
tests/regression/       compare_versions.py -- vulnerable-vs-patched assertions
tests/detection/        thresholds.py -- behavioral detection rules + self-test
tests/                  test_version_resolver.py, package/CLI/schema/lab/golden tests
reports/                generate_report.py -> technical-report.md, vulnerability-matrix.csv
evidence/metrics/       regression-results.json -- latest live A/B verdicts
config/                 research.yaml (targets, versions), lab-limits.yaml (isolation policy), vulnforge.yaml
```

## Quick start

For a full command reference (including troubleshooting and extension
steps), see [`usage.md`](usage.md).

```bash
# 0. Create and activate a venv, then install the factory (editable)
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e '.[dev]'          # runtime deps + jsonschema + pytest + vulnforge CLI

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

# 3. Run a PoC directly
python3 probes/http1/poc_111101_chunk_amplification.py --n-chunks 20000 --target both
python3 probes/http2/poc_116078_data_frame_amplification.py --n-frames 20000 --target both

# 4. Run it as a pass/fail regression (A/B + assertion)
python3 tests/regression/compare_versions.py --all --json-out evidence/metrics/regression-results.json

# 5. Tear down
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
   and its fixing commit diff on GitHub (linked from the advisory and from
   `data/advisories.json`) to pin down the exact mechanism.
3. Copy the closest existing PoC in `probes/` as a starting point -- the
   HTTP/1 and HTTP/2 amplification PoCs share an in-flight
   `/admin/stats` peak-memory comparison pattern that generalizes to most
   of the resource-exhaustion family. The WebSocket family needs a
   `websocket` client (see the stub endpoint already wired in
   `lab/app/lib/lab_app/router.ex`'s `/ws/echo`); the smuggling family
   needs a second "front-end" process (e.g. a reverse proxy container) in
   front of Bandit, since smuggling impact is a property of the pair, not
   Bandit alone -- see the analyst note on CVE-2026-114216.
4. Register the new probe in `probes/registry.py` with the correct
   vulnerable/patched target pair and amplification thresholds.
5. Re-run `reports/generate_report.py` -- the PoC-coverage note in
   Section 5 of the report updates automatically from that registry.

## Best practices this scaffold enforces

- Advisory data is the single source of truth (`data/advisories.json`);
  the report, matrix, and lab-checkpoint plan are all *generated* from it,
  never hand-edited independently.
- CVSS is preserved verbatim and never blended into the priority score.
- Every regression run pairs a probe with a vulnerable target and a patched
  target in the same invocation (`probes/registry.py` records the pair;
  `compare_versions.py` refuses to treat a non-reproducing probe as success).
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
- Lab containers are disposable, capability-dropped, resource-capped, and
  loopback-only by default.
