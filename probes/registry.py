"""
Shared probe registry.

Both the regression harness (`tests/regression/compare_versions.py`) and the
report generator (`reports/generate_report.py`) read this file, so a PoC is
registered exactly once. Each entry describes:

  module                        path to the probe module
  func                          callable in that module taking (target, **kwargs)
  kwargs                        default probe arguments
  vulnerable_min_amplification  minimum effect expected on the vulnerable target
  patched_max_amplification     maximum effect tolerated on the patched target
  vulnerable_target             config/research.yaml target name for the vulnerable side
  patched_target                config/research.yaml target name for the patched side

CVE-2026-116078 is fixed only in 1.14.1, so its vulnerable side is the 1.14.0
"interim" target. Using 1.13.1 would conflate this fix with all the 1.14.0
fixes and prove nothing about the 1.14.1 change.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

PROBE_REGISTRY = {
    "CVE-2026-111101": dict(
        module=REPO_ROOT / "probes" / "http1" / "poc_111101_chunk_amplification.py",
        func="run",
        # NOTE: this probe is registered but its A/B result is INCONCLUSIVE.
        # At 5k chunks the send completes in ~30 ms, below the sampler's
        # resolution; a paced 20k run is long enough to measure and shows
        # *both* 1.13.1 and 1.14.1 growing by megabytes against the
        # large-chunk control. The metric therefore does not isolate the
        # 1.14.0 fix. See reports/lab-runtime-fixes.md before citing it.
        kwargs=dict(n_chunks=5000, pace_ms=0),
        vulnerable_min_amplification=3.0,
        patched_max_amplification=1.5,
        vulnerable_target="vulnerable",
        patched_target="patched",
    ),
    "CVE-2026-116078": dict(
        module=REPO_ROOT / "probes" / "http2" / "poc_116078_data_frame_amplification.py",
        func="run",
        # 5k frames is below the point where the per-frame overhead separates
        # from GC noise; 20k gives a stable peak while staying far inside the
        # lab's wire/duration budgets (~200 KB, ~2 s).
        kwargs=dict(n_frames=20000, pace_ms=0),
        vulnerable_min_amplification=3.0,
        patched_max_amplification=1.5,
        vulnerable_target="interim",
        patched_target="patched",
    ),
}
