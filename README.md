# Bandit Security Research → VulnForge

A local-first vulnerability research factory, with Bandit as its first target.
It turns advisories into reproducible packages: analysis, pinned
vulnerable/patched labs, PoCs, multi-run validation evidence, offline
detection, and generated reports. Research priority is scored independently of
CVSS.

## Current status

| CVE | Pair | Vulnerable median | Patched median | Verdict | Detection |
|---|---|---:|---:|---|---|
| CVE-2026-116078 | 1.14.0 → 1.14.1 | 7.79 MiB | 0.63 MiB | **CONFIRMED** | **TRIGGERED** |
| CVE-2026-111101 | 1.13.1 → 1.14.0 | 2.66 MiB | 1.67 MiB | **INCONCLUSIVE** (1.60x < 2.00x) | INCONCLUSIVE |

Medians are from 3 runs of the absolute attack-memory metric. 116078's run
ranges do not overlap; its detection signal is the memory-per-connection
outlier rule, which now requires both z > 3 and at least 3 MB. 111101's
corrected first-fixed pair does not meet the pre-registered 2.00x threshold and
is not a confirmed finding.

- 24 advisories triaged and prioritized; 2 packaged end-to-end; 22 remaining.
- VulnForge M0–M7 implemented. The second-target proof is a toy adapter; a real
  second production target and the full catalog-to-package source-of-truth flip
  remain future work.
- `probes/registry.py` and `tests/regression/compare_versions.py` remain for
  the legacy single-run harness; package manifests are the current source of
  truth.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

vulnforge doctor
vulnforge package validate

vulnforge lab start CVE-2026-116078
vulnforge validate CVE-2026-116078 --runs 3
vulnforge detect CVE-2026-116078
vulnforge report --all
vulnforge lab stop CVE-2026-116078

vulnforge ui                     # local dashboard on loopback
```

For the full command reference, lab lifecycle, troubleshooting, and extension
steps, see [`usage.md`](usage.md).

## What the factory does

- **Packages advisories** as self-contained `vulnerabilities/<CVE>/` trees:
  advisory, analysis, lab spec, probe, tests, detection, evidence, report.
- **Builds pinned labs** with per-version lockfiles, a digest-pinned base
  image, dynamic loopback ports, resource caps, and image/build provenance.
- **Validates A/B behavior** with repeated runs, medians, a patched-CV guard,
  non-overlapping run ranges, and forced GC between baselines.
- **Captures evidence** as raw runs, `/admin/stats` telemetry, container logs,
  image IDs, and SHA-256 artifact hashes.
- **Runs offline detection** over captured evidence and reports per-target rule
  results; only vulnerable-only signals are called discriminating.
- **Generates reports** per CVE and globally from package evidence.
- **Serves a local dashboard** (`vulnforge ui`) over the same evidence, with
  allowlisted lab/validation actions and a loopback-only server.
- **Supports intelligence work**: dry-run OSV ingestion, commit-diff capture
  and root-cause scaffolds, and data-driven prioritization.

## Safety

Probes only target loopback lab containers. The lab binds ports to
`127.0.0.1`, drops capabilities, sets `read_only`, applies CPU/memory/PID caps,
and has no restart policy. `ERL_AFLAGS="+Q 262144"` is required so OTP 27 does
not reserve ~1.5 GiB for the port table. The lab network is a dedicated bridge
but not `internal: true`, because Docker drops published port mappings on
internal networks; use explicit firewall rules for a hard egress block.

Policy: [`config/lab-limits.yaml`](config/lab-limits.yaml).
Runtime notes: [`reports/lab-runtime-fixes.md`](reports/lab-runtime-fixes.md).

## Docs

| Document | Purpose |
|---|---|
| [`usage.md`](usage.md) | Full CLI, lab, validation, troubleshooting |
| [`docs/package-lifecycle.md`](docs/package-lifecycle.md) | Lifecycle diagram, package invariants, add-a-CVE/adapter checklist |
| [`docs/vulnforge-architecture.md`](docs/vulnforge-architecture.md) | Architecture, contracts, roadmap, known gaps |
| [`docs/package-authoring.md`](docs/package-authoring.md) | Add a vulnerability package |
| [`docs/adapter-authoring.md`](docs/adapter-authoring.md) | Add a target adapter |
| [`docs/ingestion.md`](docs/ingestion.md) | OSV ingestion and source analysis |
| [`docs/verdicts.md`](docs/verdicts.md) | Validation modes and verdict predicates |
| [`docs/ci.md`](docs/ci.md) | Local checks, CI, gated Docker tests |

## Extending

Pick the next item from `reports/technical-report.md`, add its score in
`data/prioritization.json`, scaffold it with
`vulnforge package scaffold <CVE>`, implement the generated probe, and run
`vulnforge analyze`, `vulnforge validate`, `vulnforge detect`, and
`vulnforge report`. The exact file checklist, lifecycle, invariants, and
copy-vs-change table are in
[`docs/package-lifecycle.md`](docs/package-lifecycle.md).

## Development

```bash
pytest -q
ruff check src tests
VULNFORGE_DOCKER=1 python -m unittest tests.test_lab_integration -v
```

CI and the gated Docker matrix are described in [`docs/ci.md`](docs/ci.md).
