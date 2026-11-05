# Vulnerability packages

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
│   ├── compose.yaml       # manual fallback (fixed ports)
│   └── provenance.json    # generated: base digest, lock hashes, image IDs
├── poc/
│   ├── manifest.json      # entrypoint, target roles, metric, thresholds
│   ├── exploit.py         # run(target, **kwargs)
│   └── README.md
├── tests/                 # package-local vulnerable/patched/contract tests (M3)
├── detection/
│   ├── spec.json          # rule mapping and expectations
│   └── evidence.json      # generated rule results (M4)
├── evidence/
│   ├── execution.json     # command, environment, verdict, hashes
│   └── raw-regression.json
└── report.md
```

## Source of truth in M0–M4

`data/advisories.json` remains the global advisory catalog. The per-package
`advisory.json` is a **materialized view**; `vulnforge package validate`
checks it for drift. M5 flips the source of truth to the package and makes the
global catalog a generated index.

## Add a package

1. Create `vulnerabilities/<CVE>/` with the layout above.
2. Copy the advisory from `data/advisories.json`, add
   `"schema_version": "1.0"` and a `provenance` block.
3. Set `package.json` versions to **last vulnerable** and **first fixed**.
4. Point `lab/lab.json` at both targets and keep the same app/config.
5. Register the probe in `poc/manifest.json`.
6. Validate:

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
- `lab/compose.yaml` exists (manual fallback) and `lab/provenance.json` is
  schema-valid when present;
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

| CVE | Target | Status | Pair | Metric | Verdict |
|---|---|---|---|---|---|
| CVE-2026-116078 | bandit | validated | 1.14.0 -> 1.14.1 | attack memory | CONFIRMED (8.03 MB vs 0.55 MB) |
| CVE-2026-111101 | bandit | inconclusive | 1.13.1 -> 1.14.0 | attack memory | INCONCLUSIVE (1.60x < 2.00x) |
