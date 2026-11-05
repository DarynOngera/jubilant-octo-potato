# Verdicts

`vulnforge validate` runs the package probe N times against the vulnerable and
patched targets, then decides from medians, not a single run.

## Modes

### Absolute

```json
{
  "mode": "absolute",
  "vulnerable_min": 3000000,
  "patched_max": 1500000,
  "min_samples": 3,
  "max_cv": 0.35
}
```

Confirmed when:

- vulnerable median >= `vulnerable_min`
- patched median <= `patched_max`
- patched CV <= `max_cv`
- run ranges do not overlap

### Relative

```json
{
  "mode": "relative",
  "vulnerable_min": 1000000,
  "patched_max": 10000000,
  "min_ratio": 2.0,
  "min_samples": 3,
  "max_cv": 0.35
}
```

Confirmed when:

- vulnerable median >= the sanity floor
- `vulnerable_median / patched_median >= min_ratio`
- patched median is below the sanity cap

## Outcomes

- `CONFIRMED` — predicate met.
- `FAIL` — patched target still above the maximum/sanity cap.
- `INCONCLUSIVE` — not enough samples, patched CV too high, overlapping ranges,
  or relative reduction below the pre-registered threshold.
- `ERROR` — a probe run failed; partial evidence is preserved.

Exit code is `0` only for `CONFIRMED`.

## Current results

| CVE | Pair | Metric | Vulnerable median | Patched median | Runs | Verdict |
|---|---|---|---:|---:|---|---|
| CVE-2026-116078 | 1.14.0 -> 1.14.1 | attack memory | 5.03 MiB | 0.58 MiB | 3 | CONFIRMED |
| CVE-2026-111101 | 1.13.1 -> 1.14.0 | attack memory | 2.66 MiB | 1.67 MiB | 3 | INCONCLUSIVE (1.60x < 2.00x) |

Never lower a threshold after seeing the data. If the metric does not meet the
pre-registered predicate, the package stays inconclusive.
