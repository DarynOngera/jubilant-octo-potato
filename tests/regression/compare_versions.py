#!/usr/bin/env python3
"""
compare_versions.py

Patch-verification harness: runs a given probe module against its registered
vulnerable and patched lab targets and asserts the amplification/behavior
collapses once patched. This is what turns a PoC into a *validated*
finding rather than an anecdote, and it's also the CI-style regression
test you re-run after bumping the pinned Bandit version in lab/compose.yaml.

Each probe's A/B pair comes from probes/registry.py, so a CVE fixed later
than the primary "vulnerable" checkpoint can be paired with an interim
version instead (e.g. CVE-2026-116078 uses 1.14.0 vs 1.14.1).

Usage:
    python3 tests/regression/compare_versions.py --cve CVE-2026-111101
    python3 tests/regression/compare_versions.py --all
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "probes"))
from common import require_lab_target  # noqa: E402
from registry import PROBE_REGISTRY  # noqa: E402


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_one(cve: str) -> dict:
    spec = PROBE_REGISTRY[cve]
    mod = _load_module(spec["module"])
    func = getattr(mod, spec["func"])

    vulnerable_target = spec.get("vulnerable_target", "vulnerable")
    patched_target = spec.get("patched_target", "patched")
    if vulnerable_target == patched_target:
        raise SystemExit(
            f"REFUSING: {cve} pairs '{vulnerable_target}' with itself; "
            f"a patched control must be a different target"
        )
    vuln = require_lab_target(vulnerable_target, allow_single=True)[0]
    patched = require_lab_target(patched_target, allow_single=True)[0]

    results = {
        "vulnerable": func(vuln, **spec["kwargs"]),
        "patched": func(patched, **spec["kwargs"]),
    }

    verdict = "PASS"
    reasons = []

    vuln_amp = results["vulnerable"]["amplification_factor"]
    patched_amp = results["patched"]["amplification_factor"]

    if vuln_amp < spec["vulnerable_min_amplification"]:
        verdict = "INCONCLUSIVE"
        reasons.append(
            f"vulnerable target amplification {vuln_amp:.2f}x below expected "
            f"minimum {spec['vulnerable_min_amplification']}x -- bug may not "
            f"be reproducing as described; re-check preconditions"
        )
    if patched_amp > spec["patched_max_amplification"]:
        verdict = "FAIL"
        reasons.append(
            f"patched target still shows amplification {patched_amp:.2f}x "
            f"(expected <= {spec['patched_max_amplification']}x) -- fix may "
            f"not be effective, or wrong patched version is pinned"
        )
    if vuln_amp >= spec["vulnerable_min_amplification"] and patched_amp <= spec["patched_max_amplification"]:
        verdict = "CONFIRMED"

    return {
        "cve": cve,
        "verdict": verdict,
        "reasons": reasons,
        "vulnerable_target": vulnerable_target,
        "patched_target": patched_target,
        "vulnerable_amplification": vuln_amp,
        "patched_amplification": patched_amp,
        "raw_results": results,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cve", type=str, help="single CVE id, e.g. CVE-2026-111101")
    ap.add_argument("--all", action="store_true", help="run every registered probe")
    ap.add_argument("--json-out", type=str, default=None)
    args = ap.parse_args()

    if not args.cve and not args.all:
        ap.error("pass --cve <id> or --all")
    if args.cve and args.cve not in PROBE_REGISTRY:
        ap.error(
            f"{args.cve} has no registered probe "
            f"(known: {', '.join(sorted(PROBE_REGISTRY))})"
        )

    cves = list(PROBE_REGISTRY) if args.all else [args.cve]
    all_results = []
    for cve in cves:
        if cve not in PROBE_REGISTRY:
            print(f"SKIP {cve}: no probe registered yet")
            continue
        print(f"\n### {cve} ###")
        r = run_one(cve)
        all_results.append(r)
        print(f"Verdict: {r['verdict']}")
        for reason in r["reasons"]:
            print(f"  - {reason}")
        print(f"  vulnerable amplification: {r['vulnerable_amplification']:.2f}x")
        print(f"  patched amplification:    {r['patched_amplification']:.2f}x")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(all_results, indent=2))
        print(f"\nWrote {args.json_out}")

    # CI treats both FAIL and INCONCLUSIVE as non-success: a probe that no
    # longer reproduces is as much a problem as a patch that does not hold.
    if any(r["verdict"] != "CONFIRMED" for r in all_results):
        sys.exit(1)


if __name__ == "__main__":
    main()
