# PoC index

Package-local PoCs live under `vulnerabilities/<CVE>/poc/` and are run by the
M3 validator (`vulnforge validate`). The older scripts under `probes/` remain
for the legacy single-run harness and historical comparison.

| CVE | Script | Pair | Latest M3 result |
|---|---|---|---|
| [CVE-2026-116078](../reports/technical-report.md#cve-2026-116078) | [`vulnerabilities/CVE-2026-116078/poc/exploit.py`](../vulnerabilities/CVE-2026-116078/poc/exploit.py) | vulnerable `1.14.0` vs patched `1.14.1` | **CONFIRMED** — 3 runs, 100k 1-byte DATA frames; vulnerable median 5.03 MiB, patched median 0.58 MiB; detection TRIGGERED |
| [CVE-2026-111101](../reports/technical-report.md#cve-2026-111101) | [`vulnerabilities/CVE-2026-111101/poc/exploit.py`](../vulnerabilities/CVE-2026-111101/poc/exploit.py) | vulnerable `1.13.1` vs patched `1.14.0` | **INCONCLUSIVE** — 3 runs, 20k 1-byte chunks; corrected first-fixed pair shows 1.60x reduction, below the pre-registered 2.00x threshold; detection INCONCLUSIVE |

Run the M3 validator after starting the lab:

```bash
vulnforge lab start CVE-2026-116078
vulnforge validate CVE-2026-116078 --runs 3
vulnforge lab stop CVE-2026-116078
```

Evidence bundles are under `vulnerabilities/<CVE>/evidence/`. The legacy
registry remains in `probes/registry.py`; the package manifests are the M3
source of truth.
