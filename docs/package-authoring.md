# Package authoring

A package is one self-contained CVE directory under `vulnerabilities/`.

For the end-to-end lifecycle, the current required/generated file split, and a
worked example, see [`package-lifecycle.md`](package-lifecycle.md). In
particular, the Bandit adapter also needs
`lab/app/locks/mix-<version>.lock` for both pinned versions, and a probe must
emit the observation keys the offline detector consumes.

## Layout

```text
vulnerabilities/CVE-XXXX-XXXXX/
├── advisory.json
├── package.json
├── analysis/
│   ├── root-cause.md
│   ├── exploitability.json
│   └── attack-surface.md
├── lab/
│   ├── lab.json
│   ├── compose.yaml        # optional manual fallback; generated at runtime
│   └── provenance.json
├── poc/
│   ├── manifest.json
│   ├── exploit.py
│   └── README.md
├── tests/
├── detection/
│   ├── spec.json
│   └── evidence.json
├── evidence/
│   ├── execution.json
│   ├── validation.json
│   ├── runs/
│   ├── telemetry/
│   └── logs/
└── report.md
```

## Manifest

`package.json` pins:

- adapter name (`adapter`; `target` is a legacy alias)
- vulnerable, patched, and first-fixed versions
- artifact paths
- validation status/verdict
- provenance

## Probe contract

`poc/exploit.py` implements:

```python
def run(target: ProbeTarget, **kwargs) -> ProbeResult: ...
```

Use `vulnforge.probe.MemorySampler`, `Timer`, `capture_benign_pool`,
`enforce_loopback`, and the budget validators. The probe must read the dynamic
runtime; it must not hard-code host ports.

`poc/manifest.json` declares the entrypoint, target roles, kwargs, metric, and
thresholds.

## Validate

```bash
vulnforge package scaffold <CVE>
vulnforge package validate <CVE>
vulnforge lab start <CVE>
vulnforge validate <CVE> --runs 3
vulnforge detect <CVE>
vulnforge report <CVE>
vulnforge lab stop <CVE>
```

`vulnforge package validate` checks schemas, cross-file CVE/version/target
consistency, required paths, advisory drift, and status/verdict agreement.
