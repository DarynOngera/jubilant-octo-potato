# Package authoring

A package is one self-contained CVE directory under `vulnerabilities/`.

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
│   ├── compose.yaml
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

- target adapter name
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
vulnforge package validate <CVE>
vulnforge lab start <CVE>
vulnforge validate <CVE> --runs 3
vulnforge detect <CVE>
vulnforge report <CVE>
vulnforge lab stop <CVE>
```

`vulnforge package validate` checks schemas, cross-file CVE/version/target
consistency, required paths, advisory drift, and status/verdict agreement.
