# Vulnerability packages

The normative package contract, lifecycle, and add-a-package checklist are in
[`docs/package-lifecycle.md`](../docs/package-lifecycle.md). This file is a
short index; if it disagrees with that page or the code, treat it as stale.

Each directory is a self-contained research package for one CVE:

```text
CVE-XXXX-XXXXX/
├── advisory.json          # normalized advisory (schema-validated)
├── package.json           # manifest: versions, paths, status, validation
├── analysis/
│   ├── root-cause.md
│   ├── exploitability.json
│   └── attack-surface.md
├── lab/
│   ├── lab.json           # versions, targets, limits
│   ├── compose.yaml       # optional manual fallback (fixed ports)
│   └── provenance.json    # generated: base digest, lock hashes, image IDs
├── poc/
│   ├── manifest.json      # entrypoint, target roles, metric, thresholds
│   ├── exploit.py         # run(target, **kwargs)
│   └── README.md
├── tests/                 # required directory; test template not standardized yet
├── detection/
│   ├── spec.json          # rule mapping and expectations
│   └── evidence.json      # generated rule results
├── evidence/
│   ├── execution.json     # command, environment, verdict, hashes
│   ├── validation.json    # generated verdict, metrics, aggregates
│   ├── runs/              # generated raw probe results
│   ├── telemetry/         # generated /admin/stats series
│   └── logs/              # generated container logs
└── report.md              # generated; report.json is also written
```

## Source of truth in M0–M4

`data/advisories.json` remains the global advisory catalog. The per-package
`advisory.json` is a **materialized view**; `vulnforge package validate`
checks it for drift. M5 flips the source of truth to the package and makes the
global catalog a generated index.

## Add a package

1. Run `vulnforge package scaffold <CVE>` to create the draft layout,
   materialized advisory, version pair, and templates.
2. Review `package.json` versions (**last vulnerable** and **first fixed**)
   and `lab/lab.json` targets; the scaffold derives them from the catalog.
3. Implement `poc/exploit.py` and replace the placeholder metric/predicate in
   `poc/manifest.json`.
4. Replace the scaffolded detection rule in `detection/spec.json`.
5. Validate:

   ```bash
   vulnforge package validate <CVE>
   vulnforge status
   ```

The validator enforces:

- schemas for advisory, package, lab, probe, detection spec, evidence, and
  exploitability;
- CVE consistency across directory, manifest, advisory, lab, and probe;
- versions matching between manifest, lab, and the first fixed release;
- vulnerable/patched target roles existing and matching the probe;
- required analysis, detection, evidence, and test paths;
- `lab/provenance.json` is schema-valid when present; the optional manual
  `lab/compose.yaml` is not required by the loader;
- `status: validated` implies `last_verdict: CONFIRMED`;
- advisory drift against `data/advisories.json`.

## Lab lifecycle

```bash
vulnforge lab build <CVE>
vulnforge lab start <CVE>
vulnforge lab status <CVE>
vulnforge lab stop <CVE>
```

The orchestrator allocates free loopback ports, namespaces the Compose project
and containers per CVE, builds with per-version lockfiles, and records image
provenance in the package's `lab/provenance.json`.

## Validation lifecycle

```bash
vulnforge lab start <CVE>
vulnforge poc run <CVE>
vulnforge validate <CVE> --runs 3
vulnforge lab stop <CVE>
```

`vulnforge validate` writes `evidence/validation.json`, per-run and telemetry
files, logs, and a hash manifest in `evidence/execution.json`, then updates the
package status/verdict. It exits non-zero unless the verdict is `CONFIRMED`.

Verdict modes:

- `absolute` — vulnerable median >= minimum, patched median <= maximum,
  non-overlapping run ranges, patched CV within the guard.
- `relative` — vulnerable/patched median ratio >= the pre-registered minimum.

## Current packages

| CVE | Target | Status | Pair | Metric | Verdict | Detection |
|---|---|---|---|---|---|---|
| CVE-2026-116078 | bandit | validated | 1.14.0 -> 1.14.1 | attack memory | CONFIRMED (7.79 MiB vs 0.63 MiB) | TRIGGERED |
| CVE-2026-111101 | bandit | inconclusive | 1.13.1 -> 1.14.0 | attack memory | INCONCLUSIVE (1.60x < 2.00x) | INCONCLUSIVE |
