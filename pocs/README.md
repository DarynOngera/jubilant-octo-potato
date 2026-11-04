# PoC index

Implemented PoCs live next to the harness code in `probes/`, since each one
depends on `probes/common.py` for target resolution and lab-isolation
guardrails. This file is the index the deliverable list promised.

| CVE | Script | Regression pair | Latest live A/B |
|---|---|---|---|
| [CVE-2026-111101](../reports/technical-report.md#cve-2026-111101) | [`probes/http1/poc_111101_chunk_amplification.py`](../probes/http1/poc_111101_chunk_amplification.py) | vulnerable `1.13.1` vs patched `1.14.1` | **INCONCLUSIVE** -- both versions show per-chunk growth; metric does not isolate the fix |
| [CVE-2026-116078](../reports/technical-report.md#cve-2026-116078) | [`probes/http2/poc_116078_data_frame_amplification.py`](../probes/http2/poc_116078_data_frame_amplification.py) | interim `1.14.0` vs patched `1.14.1` | **CONFIRMED** -- historical single run 8.90x vs 0.58x; M3 multi-run median pending (a later single run was noisy) |

Both require the lab running first (`docker compose -f lab/compose.yaml up -d`,
which starts the interim 1.14.0 target as well). Registry entries live in
`probes/registry.py`; raw results are in `evidence/metrics/`.

See `README.md` "Extending to the remaining advisories" for the pattern to
add PoCs for the other 22.
