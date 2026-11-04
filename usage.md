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

# 5. Live A/B regression
.venv/bin/python tests/regression/compare_versions.py \
  --all --json-out evidence/metrics/regression-results.json
```

The regression command exits non-zero unless **every** probe is
`CONFIRMED`. As of 2026-11-04, `--all` exits `1` because CVE-2026-111101 is
`INCONCLUSIVE`; use `--cve CVE-2026-116078` for a currently green run. See
[Regression harness](#regression-harness) for verdicts.

---

## Repository map

| Path | Purpose |
|---|---|
| `data/advisories.json` | Source of truth for the 24 advisories |
| `data/version-cve-map.json` | Generated: every known release -> vulnerable CVEs |
| `data/lab-checkpoints.json` | Generated: deduplicated A/B checkpoint plan |
| `data/vulnerability-matrix.json` | Generated: priority-scored advisory matrix |
| `src/vulnforge/` | Factory package: CLI, config, models, schemas, package validation |
| `vulnerabilities/` | Self-contained research packages, one directory per CVE |
| `schemas/` | JSON Schemas for advisory, package, lab, probe, validation, detection, evidence |
| `docs/` | Architecture and authoring documentation |
| `triage/version_resolver.py` | Multi-range parser, exposure map, checkpoints |
| `triage/prioritizer.py` | I/E/R/D scores + `priority_P` ranking |
| `reports/generate_report.py` | Builds `reports/technical-report.md` |
| `probes/common.py` | Target guardrails, budgets, in-flight memory sampler |
| `probes/registry.py` | Single registry of PoCs, target pairs, thresholds |
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

## VulnForge factory CLI (M1/M2)

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
| `vulnforge triage` | M2 (version-plan extraction) |
| `vulnforge poc` | M3 |
| `vulnforge validate` | M3 |
| `vulnforge detect` | M4 |
| `vulnforge report` | M4 |
| `vulnforge ingest` | M5 |

`vulnforge lab` is implemented in M2. The stubs exit `2` with a message naming
the milestone; they do not silently do nothing. See
`docs/vulnforge-architecture.md` for the full design.

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
└── report.md
```

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
`config/research.yaml`, and `probes/registry.py`. If
`evidence/metrics/regression-results.json` exists, Section 5 includes the
latest live A/B verdicts. Re-run this after changing advisories, scores,
PoCs, or regression results.

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
# All Python unit tests (52 currently; 1 Docker integration test skipped by default)
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

```bash
# CVE-2026-111101: HTTP/1 1-byte chunks
.venv/bin/python probes/http1/poc_111101_chunk_amplification.py \
  --n-chunks 20000 --pace-ms 1 --target both

# CVE-2026-116078: HTTP/2 1-byte DATA frames
.venv/bin/python probes/http2/poc_116078_data_frame_amplification.py \
  --n-frames 20000 --pace-ms 0 --target both
```

`--target both` is **not** always 1.13.1 vs 1.14.1:

| Probe | `both` expands to |
|---|---|
| `poc_111101...` | vulnerable `1.13.1` vs patched `1.14.1` |
| `poc_116078...` | interim `1.14.0` vs patched `1.14.1` |

Single targets are refused by default because
`config/lab-limits.yaml` sets `require_patched_control: true`. Use
`--target both`, or the regression harness (which pairs targets
explicitly and passes `allow_single=True` internally).

The PoCs print a summary but do **not** assert a verdict; the regression
harness is what turns a run into pass/fail. Each run enforces:

- `max_request_bytes_total: 268435456` (256 MiB)
- `max_duration_seconds: 120`

If a run is too large, reduce the chunk/frame count or pacing.

> A run that completes in under ~50 ms may yield only one memory sample.
> That is a measurement limitation, not proof the bug is fixed. Increase
> `--pace-ms` or the count for a stable peak.

---

## 5. Regression harness

```bash
# One CVE (errors if it is not registered)
.venv/bin/python tests/regression/compare_versions.py --cve CVE-2026-116078

# Every registered probe
.venv/bin/python tests/regression/compare_versions.py \
  --all --json-out evidence/metrics/regression-results.json
```

For each CVE it reads `probes/registry.py`, runs the probe against the
registered vulnerable and patched targets, then compares the
amplification factors:

| Verdict | Meaning |
|---|---|
| `CONFIRMED` | Vulnerable amp >= `vulnerable_min_amplification` **and** patched amp <= `patched_max_amplification` |
| `FAIL` | Patched target is still above `patched_max_amplification` |
| `INCONCLUSIVE` | Vulnerable target is below `vulnerable_min_amplification`; preconditions or measurement need work |

Exit status is `0` only if every result is `CONFIRMED`. Both `FAIL` and
`INCONCLUSIVE` exit `1`: a probe that stops reproducing is as important
as a patch that does not hold.

### Current live results (2026-11-04)

| CVE | Pair | Vulnerable | Patched | Verdict |
|---|---|---|---|---|
| CVE-2026-116078 | 1.14.0 vs 1.14.1 | 8.90x | 0.58x | **CONFIRMED** |
| CVE-2026-111101 | 1.13.1 vs 1.14.1 | 1.01x | 0.37x | **INCONCLUSIVE** |

CVE-2026-111101 is implemented but **not** a confirmed finding. At 20k
chunks with pacing, both 1.13.1 and 1.14.1 grow by megabytes against the
large-chunk control, so the current metric does not isolate the 1.14.0
fix. See `reports/lab-runtime-fixes.md`.

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

1. Create a module under `probes/http1/`, `probes/http2/`, etc.
2. Use `probes/common.py`:

   - `require_lab_target(...)` (never accept an arbitrary host/port)
   - `MemorySampler` to capture peak in-flight `erlang_memory.total`
   - `validate_payload_budget(...)` and `validate_duration_budget(...)`
   - `Timer`, `Target`

3. Register it in `probes/registry.py`:

   ```python
   "CVE-2026-XXXXXX": dict(
       module=REPO_ROOT / "probes" / "http1" / "poc_XXXXXX.py",
       func="run",
       kwargs=dict(n_chunks=20000, pace_ms=0),
       vulnerable_min_amplification=3.0,
       patched_max_amplification=1.5,
       vulnerable_target="vulnerable",  # or "interim"
       patched_target="patched",
   )
   ```

4. Run the harness, then regenerate the report:

   ```bash
   .venv/bin/python tests/regression/compare_versions.py --cve CVE-2026-XXXXXX
   .venv/bin/python reports/generate_report.py
   ```

The registry is the single source of truth for the harness and the
report's PoC-coverage section. Direct-PoC defaults and registry kwargs can
differ; the harness uses the registry values.

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
| `INCONCLUSIVE` verdict | The vulnerable side did not amplify enough. Increase count/pacing, re-check the target version, or redesign the probe. Do not lower thresholds just to pass. |
| 111101 shows huge amplification on both targets | Known limitation; see `reports/lab-runtime-fixes.md`. |
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
