# Usage

Practical command reference for the Bandit security research pipeline.
Everything here is run from the repository root:

```bash
cd /home/ongera/sec/bandit-security-research
```

The examples use `.venv/bin/python` so they work without activating the
virtualenv. If you have activated it, `python3` is equivalent.

> **Safety:** PoCs only talk to loopback targets declared in
> `config/research.yaml`. `probes/common.py` refuses non-`127.0.0.1`
> hosts and names containing `prod`, `staging`, or `live`. Do not
> bypass that guard.

---

## Quick start

```bash
# 1. Python environment
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'

# 2. Regenerate triage data + report
.venv/bin/python triage/version_resolver.py
.venv/bin/python triage/prioritizer.py --csv reports/vulnerability-matrix.csv
.venv/bin/python reports/generate_report.py

# 3. Tests
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
.venv/bin/python tests/detection/thresholds.py
.venv/bin/vulnforge package validate

# 4. Lab
docker compose -f lab/compose.yaml build
docker compose -f lab/compose.yaml up -d
curl http://127.0.0.1:4100/healthz   # 1.13.1
curl http://127.0.0.1:4120/healthz   # 1.14.0
curl http://127.0.0.1:4110/healthz   # 1.14.1

# 5. Factory A/B validation (dynamic lab, 3 runs)
vulnforge lab start CVE-2026-116078
vulnforge validate CVE-2026-116078 --runs 3
vulnforge lab stop CVE-2026-116078

# 6. Legacy single-run harness (historical comparison)
.venv/bin/python tests/regression/compare_versions.py \
  --all --json-out evidence/metrics/regression-results.json
```

`vulnforge validate` exits non-zero unless the verdict is `CONFIRMED`. As of
2026-11-04, CVE-2026-116078 is `CONFIRMED` and CVE-2026-111101 is
`INCONCLUSIVE` at a 1.60x reduction. See [Regression harness](#regression-harness)
for verdicts and [Factory validation](#factory-validation-m3) for the
multi-run workflow.

---

## Repository map

| Path | Purpose |
|---|---|
| `data/advisories.json` | Source of truth for the 24 advisories |
| `data/version-cve-map.json` | Generated: every known release -> vulnerable CVEs |
| `data/lab-checkpoints.json` | Generated: deduplicated A/B checkpoint plan |
| `data/vulnerability-matrix.json` | Generated: priority-scored advisory matrix |
| `src/vulnforge/` | Factory package: CLI, config, models, schemas, package validation |
| `src/vulnforge/probe/` | Probe protocol, target model, memory sampler, budgets |
| `src/vulnforge/validate/` | Multi-run statistics, verdict logic, evidence bundling |
| `vulnerabilities/` | Self-contained research packages, one directory per CVE |
| `vulnerabilities/<CVE>/evidence/` | M3 validation bundle: runs, telemetry, logs, hashes |
| `schemas/` | JSON Schemas for advisory, package, lab, probe, validation, detection, evidence |
| `docs/` | Architecture and authoring documentation |
| `triage/version_resolver.py` | Multi-range parser, exposure map, checkpoints |
| `triage/prioritizer.py` | I/E/R/D scores + `priority_P` ranking |
| `reports/generate_report.py` | Builds `reports/technical-report.md` |
| `probes/common.py` | Target guardrails, budgets, in-flight memory sampler |
| `probes/registry.py` | Legacy single-run registry (historical; package manifests are M3 source of truth) |
| `tests/regression/compare_versions.py` | Runs each PoC against its A/B pair |
| `tests/detection/thresholds.py` | Four behavioral detection rules + self-test |
| `tests/test_version_resolver.py` | 18 range/parser/checkpoint unit tests |
| `tests/test_package_model.py` etc. | Package, CLI, schema, lab-plan, and golden tests |
| `lab/app/` | Version-parameterized Plug/Bandit target image |
| `lab/app/locks/` | Per-version `mix.lock` files for reproducible builds |
| `lab/compose.yaml` | Manual fixed-port lab (three targets, resource caps) |
| `.vulnforge/` | Generated runtime compose/runtime state (gitignored) |
| `vulnerabilities/<CVE>/lab/provenance.json` | Base digest, lock hashes, image IDs, git revision |
| `config/research.yaml` | Target URLs and pinned versions |
| `config/vulnforge.yaml` | Factory paths, validation defaults, target adapters |
| `config/lab-limits.yaml` | Isolation rules, resource and experiment budgets |
| `evidence/metrics/` | Regression JSON outputs (gitignored except `.gitkeep`) |
| `reports/lab-runtime-fixes.md` | Standalone report for the OTP/VM and lab fixes |

Generated artifacts should not be hand-edited; re-run the generator.

---

## VulnForge factory CLI (M1/M2/M3)

The factory package is installed editable with `pip install -e '.[dev]'`.
It is also runnable as `python -m vulnforge`.

```bash
# High-level package status
vulnforge status
vulnforge status --json

# Package inspection
vulnforge package list
vulnforge package show CVE-2026-116078
vulnforge package show CVE-2026-116078 --json

# Schema + cross-file validation (all packages, or one)
vulnforge package validate
vulnforge package validate CVE-2026-116078
vulnforge package validate --all --json

# Lab lifecycle (M2): dynamic loopback ports + provenance
vulnforge lab build CVE-2026-116078
vulnforge lab start CVE-2026-116078
vulnforge lab status CVE-2026-116078
vulnforge lab status CVE-2026-116078 --json
vulnforge lab stop CVE-2026-116078

# Probe and multi-run validation (M3)
vulnforge poc run CVE-2026-116078
vulnforge poc run CVE-2026-116078 --role patched --json
vulnforge validate CVE-2026-116078 --runs 3
vulnforge validate CVE-2026-116078 --runs 3 --aa-control
```

`vulnforge package validate` checks:

- JSON Schema conformance for advisory, package, lab, probe, detection spec,
  evidence, exploitability, and provenance;
- CVE consistency across directory name, package manifest, advisory, lab, and
  probe;
- vulnerable/patched versions matching between the manifest and lab, and
  `patched == first_fixed` (M1 rule);
- lab target roles existing and matching the probe's target names;
- required analysis, detection, evidence, and test paths;
- `lab/compose.yaml` exists and `lab/provenance.json` is schema-valid when
  present;
- `status: validated` agreeing with `last_verdict: CONFIRMED`;
- the package advisory being in sync with `data/advisories.json`.

The remaining factory commands are explicit stubs:

| Command | Planned milestone |
|---|---|
| `vulnforge triage` | version-plan extraction |
| `vulnforge detect` | M4 |
| `vulnforge report` | M4 |
| `vulnforge ingest` | M5 |

`vulnforge lab`, `vulnforge poc`, and `vulnforge validate` are implemented in
M2/M3. The stubs exit `2` with a message naming the milestone; they do not
silently do nothing. See `docs/vulnforge-architecture.md` for the full design.

### Package layout

```text
vulnerabilities/CVE-2026-116078/
├── advisory.json
├── package.json
├── analysis/
├── lab/
├── poc/
├── tests/
├── detection/
├── evidence/
│   ├── execution.json
│   ├── validation.json
│   ├── runs/
│   ├── telemetry/
│   └── logs/
└── report.md
```

The same structure exists for `CVE-2026-111101`. Package probes are the M3
source of truth; `probes/registry.py` remains for the legacy single-run
harness.

`data/advisories.json` is still the global source of truth in M0–M4. The
package `advisory.json` is a materialized, drift-checked view; M5 flips the
source of truth to the package and generates the global index.

---

## 1. Environment and data generation

### Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

Runtime dependencies: `packaging`, `pyyaml`, `h2`, `jsonschema`. The editable
install also puts the `vulnforge` command in `.venv/bin/`. Tests use the
standard-library `unittest` runner; `pytest` is installed by the `dev` extra
but is optional.

### Version/exposure resolution

```bash
# Write BOTH generated artifacts and print them
.venv/bin/python triage/version_resolver.py

# Only one artifact
.venv/bin/python triage/version_resolver.py --list
.venv/bin/python triage/version_resolver.py --checkpoints

# Compact exposure bands (read-only)
.venv/bin/python triage/version_resolver.py --summary

# CI drift check: exit 1 if data/version-cve-map.json or
# data/lab-checkpoints.json is stale
.venv/bin/python triage/version_resolver.py --check
```

The resolver treats an advisory's affected ranges as a **union**. It
accepts:

- one string: `">= 0.3.1 and < 1.14.1"`
- HTML-escaped comparators: `"&gt;= 0.3.1 and &lt; 1.14.1"`
- a list of strings: `[">= 1.0 and < 1.2", ">= 2.0 and < 2.1"]`
- OSV-style objects: `[{"introduced": "1.0.0", "fixed": "1.2.0"}]`
- an `affected_ranges` field on an advisory (preferred when present)

`affected` is kept as a compatibility scalar; for a multi-range advisory
it should be the broadest range. `affected_ranges` carries the full list.

### Priority matrix

```bash
.venv/bin/python triage/prioritizer.py --csv reports/vulnerability-matrix.csv
```

Writes `data/vulnerability-matrix.json` and, with `--csv`, the CSV. Every
CVE in `SCORES` must exist in `data/advisories.json`; add both together
when introducing a new advisory.

### Report

```bash
.venv/bin/python reports/generate_report.py
```

Reads `data/advisories.json`, `data/vulnerability-matrix.json`,
`config/research.yaml`, `probes/registry.py`, package `poc/manifest.json`
files, and package `evidence/validation.json` files. Section 5 includes the
latest M3 multi-run verdicts and falls back to legacy single-run results only
when no package validation exists. Re-run this after changing advisories,
scores, PoCs, or validation evidence.

Typical full regeneration:

```bash
.venv/bin/python triage/version_resolver.py
.venv/bin/python triage/prioritizer.py --csv reports/vulnerability-matrix.csv
.venv/bin/python reports/generate_report.py
.venv/bin/python triage/version_resolver.py --check
```

---

## 2. Tests and detection self-test

```bash
# All Python unit tests (76 currently; 1 Docker integration test skipped by default)
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'

# Real Docker build/start/status/stop for the first package
VULNFORGE_DOCKER=1 .venv/bin/python -m unittest tests.test_lab_integration -v

# Single file
.venv/bin/python tests/test_version_resolver.py

# Detection rules against synthetic attacker/normal traffic
.venv/bin/python tests/detection/thresholds.py
```

The detection self-test should print four `TRIGGERED` lines:
`per_connection_frame_rate`, `memory_per_connection_outlier`,
`body_duration_vs_size`, and `unbounded_process_growth`.

---

## 3. Lab

### Build and start

```bash
docker compose -f lab/compose.yaml build
docker compose -f lab/compose.yaml up -d
```

The build needs network access for the base image and Hex dependencies.
All three targets start by default; the interim target has no Compose
profile because the regression harness needs it.

| Service | Bandit | App | Admin (`/stats`) | Role |
|---|---|---|---|---|
| `bandit-vulnerable` | 1.13.1 | `127.0.0.1:4100` | `127.0.0.1:4101` | Last October-batch vulnerable |
| `bandit-interim` | 1.14.0 | `127.0.0.1:4120` | `127.0.0.1:4121` | Vulnerable to CVE-2026-116078 only |
| `bandit-patched` | 1.14.1 | `127.0.0.1:4110` | `127.0.0.1:4111` | Fully patched |

### Verify

```bash
for p in 4100 4120 4110; do curl -sf "http://127.0.0.1:$p/healthz"; echo; done

for p in 4101 4121 4111; do
  curl -sf "http://127.0.0.1:$p/stats" \
    | .venv/bin/python -c "import sys,json; d=json.load(sys.stdin); print(d['bandit_version'], d['erlang_memory']['total'])"
done
```

Expected versions: `1.13.1`, `1.14.0`, `1.14.1`. The idle VM baseline
should be ~50 MiB, not gigabytes.

### Orchestrated package labs (M2)

For a single vulnerability package, use the factory instead of the fixed-port
repository Compose file:

```bash
vulnforge lab build CVE-2026-116078
vulnforge lab start CVE-2026-116078
vulnforge lab status CVE-2026-116078
vulnforge lab stop CVE-2026-116078
```

The orchestrator:

- allocates free `127.0.0.1` ports for each target;
- writes the generated Compose file and runtime URLs under
  `.vulnforge/labs/<cve>/`;
- namespaces the Compose project, network, containers, and image tags per CVE;
- builds with `lab/app/locks/mix-<version>.lock` and the digest-pinned base
  image;
- waits for `/healthz` and verifies `/stats` reports the expected Bandit
  version;
- records `vulnerabilities/<cve>/lab/provenance.json` with the Dockerfile hash,
  base image, lockfile hashes, build args, OCI labels, image IDs, and git
  revision.

`vulnforge lab status --json` prints the dynamic app/admin URLs and per-target
health/version state. The existing `config/research.yaml` targets still point at
the fixed-port repository lab (4100/4110/4120); probe-to-runtime wiring lands in
M3.

### Lab constraints you must not remove

- **`ERL_AFLAGS="+Q 262144"`** is set in both Dockerfile stages and in
  Compose. OTP 27 otherwise auto-sizes the port table from host RAM
  (~1.5 GiB); the 512 MiB containers are OOM-killed before startup, and
  PoC memory deltas are hidden. See `reports/lab-runtime-fixes.md`.
- **`labnet` is not `internal: true`.** On this Docker version an internal
  bridge drops published port mappings, so the loopback ports become
  unreachable. It is still a dedicated project bridge with all ports bound
  to `127.0.0.1`. For a hard egress block, add a firewall rule for the lab
  subnet.
- Compose sets `read_only: true`, drops all capabilities, and applies
  512 MiB / 1 CPU / 512 PID limits with no restart policy.

### Logs and state

```bash
docker compose -f lab/compose.yaml ps
docker compose -f lab/compose.yaml logs -f bandit-vulnerable
docker inspect --format 'oom={{.State.OOMKilled}} running={{.State.Running}}' bandit-vulnerable
docker port bandit-vulnerable
```

---

## 4. Running a PoC directly

Package probes read the dynamic runtime written by `vulnforge lab start`:

```bash
vulnforge lab start CVE-2026-116078
python vulnerabilities/CVE-2026-116078/poc/exploit.py --role both
vulnforge poc run CVE-2026-116078
vulnforge lab stop CVE-2026-116078
```

For the HTTP/1 package:

```bash
vulnforge lab start CVE-2026-111101
python vulnerabilities/CVE-2026-111101/poc/exploit.py --role both
vulnforge poc run CVE-2026-111101
vulnforge lab stop CVE-2026-111101
```

The legacy probes under `probes/` remain for the old harness. Their
`--target both` mapping is not the package pair; use the package manifests for
the authoritative vuln/patched versions.

Each run enforces:

- `max_request_bytes_total: 268435456` (256 MiB)
- `max_duration_seconds: 120`

If a run is too large, reduce the chunk/frame count or pacing. A run that
completes too fast may yield too few memory samples; use the package manifest's
parameters (100k frames for 116078, 20k chunks at 1 ms for 111101).

---

## 5. Factory validation (M3)

```bash
vulnforge lab start CVE-2026-116078
vulnforge validate CVE-2026-116078 --runs 3
vulnforge lab stop CVE-2026-116078
```

`vulnforge validate`:

1. Reads `.vulnforge/labs/<cve>/runtime.json` (start the lab first).
2. Loads the package probe from `poc/manifest.json`.
3. Runs the probe N times against vulnerable and patched targets.
4. Computes median, min, max, stdev, and CV per target.
5. Applies the verdict predicate from the manifest.
6. Writes `evidence/validation.json`, `evidence/runs/`,
   `evidence/telemetry/`, `evidence/logs/`, and a hash-checked
   `evidence/execution.json`.
7. Updates the package status/verdict in `package.json`.

Verdict modes:

- **absolute** — vulnerable median >= minimum, patched median <= maximum,
  non-overlapping run ranges, patched CV within the guard.
- **relative** — vulnerable/patched median ratio >= the pre-registered minimum.

`vulnforge validate` exits `0` only for `CONFIRMED`; `FAIL`, `INCONCLUSIVE`,
and `ERROR` exit `1`.

### Current multi-run results (2026-11-04)

| CVE | Pair | Metric | Vulnerable median | Patched median | Runs | Verdict |
|---|---|---|---|---:|---:|---|---|
| CVE-2026-116078 | 1.14.0 -> 1.14.1 | attack memory | 8.03 MB | 0.55 MB | 3 | **CONFIRMED** |
| CVE-2026-111101 | 1.13.1 -> 1.14.0 | attack memory | 2.80 MB | 1.75 MB | 3 | **INCONCLUSIVE** |

CVE-2026-116078: run ranges do not overlap (vulnerable 5.16–9.99 MB, patched
0.52–0.59 MB).

CVE-2026-111101: the corrected first-fixed pair shows a stable **1.60x**
reduction, below the pre-registered 2.00x threshold. This is an honest
inconclusive result, not a confirmed finding.

### Legacy single-run harness

```bash
.venv/bin/python tests/regression/compare_versions.py --cve CVE-2026-116078
.venv/bin/python tests/regression/compare_versions.py \
  --all --json-out evidence/metrics/regression-results.json
```

The legacy harness still uses `probes/registry.py` and single-run amplification
factors. It is retained for historical comparison; the M3 package validator is
the authoritative path.

---

## 6. Extending the research

### Add or correct an advisory

1. Edit `data/advisories.json`.
2. Use `affected_ranges` for multiple ranges; keep `affected` as the
   broadest scalar.
3. Add a `SCORES` entry in `triage/prioritizer.py` with `I/E/R/D` and
   `notes`.
4. Regenerate:

   ```bash
   .venv/bin/python triage/version_resolver.py
   .venv/bin/python triage/prioritizer.py --csv reports/vulnerability-matrix.csv
   .venv/bin/python reports/generate_report.py
   ```

### Add an older lab checkpoint

1. Add the release to `KNOWN_VERSIONS` in `triage/version_resolver.py`.
2. Add a target to `config/research.yaml` and a service to
   `lab/compose.yaml` with `BANDIT_VERSION` and loopback ports.
3. Regenerate checkpoints:

   ```bash
   .venv/bin/python triage/version_resolver.py --checkpoints
   .venv/bin/python triage/version_resolver.py --check
   ```

The resolver raises loudly if a `fixed_in` version is absent from
`KNOWN_VERSIONS`.

### Add a PoC

1. Create `vulnerabilities/<CVE>/poc/exploit.py`.
2. Implement `run(target, **kwargs) -> ProbeResult` using
   `vulnforge.probe`:

   - `ProbeTarget` (runtime-derived host/port/admin URL)
   - `MemorySampler` to capture peak in-flight `erlang_memory.total`
   - `enforce_loopback(...)`
   - `validate_payload_budget(...)` and `validate_duration_budget(...)`
   - `Timer`

3. Declare the probe in `vulnerabilities/<CVE>/poc/manifest.json`:

   ```json
   {
     "schema_version": "1.0",
     "cve": "CVE-2026-XXXXXX",
     "entrypoint": "poc.exploit:run",
     "targets": {"vulnerable": "vulnerable", "patched": "patched"},
     "kwargs": {"n_chunks": 20000, "pace_ms": 0},
     "metric": "attack_memory_delta",
     "thresholds": {
       "vulnerable_min": 1000000,
       "patched_max": 1000000,
       "min_samples": 3,
       "max_cv": 0.35,
       "mode": "absolute"
     },
     "runs": 3
   }
   ```

4. Run the package validation and regenerate the report:

   ```bash
   vulnforge lab start CVE-2026-XXXXXX
   vulnforge validate CVE-2026-XXXXXX --runs 3
   vulnforge lab stop CVE-2026-XXXXXX
   .venv/bin/python reports/generate_report.py
   ```

The package manifest is the source of truth for the M3 validator. The legacy
`probes/registry.py` remains for the pre-factory harness only.

---

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| All containers `Exited (137)`, `OOMKilled=true`, no logs | OTP 27 port-table reservation. Confirm `ERL_AFLAGS="+Q 262144"` is in both Dockerfile stages and Compose, then rebuild. See `reports/lab-runtime-fixes.md`. |
| Containers up, health ports refuse connections | Check `docker port`; if empty, the network is `internal: true` or was created while it was. Set `internal: false`, then `docker compose -f lab/compose.yaml down -v && up -d` (Compose does not mutate an existing network). |
| `Unsupported key(s) ... [:protocol_options]` | Use `http_1_options` / `http_2_options`, not `protocol_options`. Already fixed in `lab/app/lib/lab_app/application.ex`. |
| `REFUSING: target ... is not reachable` | Start the lab (`up -d`) and check `/healthz`. |
| `REFUSING: 'x' is a single target` | Use `--target both` or the regression harness. |
| `REFUSING: estimated wire bytes ...` | Reduce `--n-chunks` / `--n-frames`; the 256 MiB budget is in `config/lab-limits.yaml`. |
| `REFUSING: paced send would take ...` | Reduce `--pace-ms` or the count; the 120 s budget is in `config/lab-limits.yaml`. |
| `no runtime for ...` | Run `vulnforge lab start <CVE>` before `poc run` or `validate`. |
| `INCONCLUSIVE` verdict | Read `evidence/validation.json` for the reason. Common causes: vulnerable median below the floor, patched CV above the guard, overlapping run ranges, or a relative reduction below the pre-registered ratio. Fix the measurement/probe; do not lower thresholds just to pass. |
| `INCONCLUSIVE` for CVE-2026-111101 at 1.60x | Expected and honest: the corrected 1.13.1 vs 1.14.0 pair shows a stable 1.60x reduction, below the pre-registered 2.00x threshold. Do not lower the threshold post-hoc. |
| Evidence hash mismatch | Re-run `vulnforge validate` or `refresh_execution_manifest` after editing evidence; README files are excluded from the hash manifest. |
| Probe run errors | Inspect `evidence/runs/` and `evidence/logs/`; the validator records `ERROR` and preserves partial evidence. |
| `--check` reports drift | Re-run `triage/version_resolver.py` (no flags writes both artifacts). |

---

## 8. Teardown

```bash
docker compose -f lab/compose.yaml down -v
```

This removes the containers and the project network. Built images remain;
use `docker compose -f lab/compose.yaml build --no-cache` after changing the
Dockerfile.

---

## 9. Generated vs. source files

Regenerate, don't hand-edit:

- `data/version-cve-map.json` -- `triage/version_resolver.py`
- `data/lab-checkpoints.json` -- `triage/version_resolver.py`
- `data/vulnerability-matrix.json` -- `triage/prioritizer.py`
- `reports/vulnerability-matrix.csv` -- `triage/prioritizer.py --csv`
- `reports/technical-report.md` -- `reports/generate_report.py`
- `evidence/metrics/regression-*.json` -- `tests/regression/compare_versions.py --json-out`

`evidence/metrics/*` is gitignored except `.gitkeep`; keep the raw JSON
locally or force-add it if a result needs to be archived.
