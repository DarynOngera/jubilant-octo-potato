# Golden baselines

These files freeze the M0 behavior of the existing Bandit pipeline. They are
intentionally checked in so a refactor that changes version resolution, the
priority matrix, or the report structure fails loudly.

| File | Source |
|---|---|
| `version-cve-map.json` | `python3 triage/version_resolver.py --list` |
| `lab-checkpoints.json` | `python3 triage/version_resolver.py --checkpoints` |
| `vulnerability-matrix.json` | `python3 triage/prioritizer.py` |
| `technical-report.sections.txt` | `grep '^## ' reports/technical-report.md` |

The report baseline is section headings only, because the generated report
contains the current date. Compare full report output only within a fixed-date
regeneration, which lands with the report refactor in M2.

When a change intentionally alters one of these artifacts, regenerate the
artifact and copy it here in the same commit, with a note in the commit
message explaining why.
