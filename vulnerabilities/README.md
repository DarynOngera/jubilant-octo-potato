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
│   └── compose.yaml       # rendered/generated lab (M2)
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

- schemas for advisory, package, lab, and probe;
- CVE consistency across directory, manifest, advisory, lab, and probe;
- versions matching between manifest, lab, and the first fixed release;
- vulnerable/patched target roles existing and matching the probe;
- required analysis, detection, evidence, and test paths;
- `status: validated` implies `last_verdict: CONFIRMED`;
- advisory drift against `data/advisories.json`.

## Current packages

| CVE | Target | Status | Pair | Verdict |
|---|---|---|---|---|
| CVE-2026-116078 | bandit | validated | 1.14.0 -> 1.14.1 | CONFIRMED |
