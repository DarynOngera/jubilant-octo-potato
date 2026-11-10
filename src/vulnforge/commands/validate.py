"""Multi-run validation CLI command."""
from __future__ import annotations

import argparse
import json
import sys

from ..config import FactoryConfig
from ..errors import PackageError
from ..packages import find_package, validate_package
from ..paths import Paths
from ..validate import run_validation


def _cmd_validate(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    try:
        pkg = find_package(paths, args.cve, enforce_status_artifacts=False)
    except PackageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    errors = validate_package(pkg, paths)
    if errors:
        print(f"package {pkg.cve} is invalid:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    if args.runs is not None and args.runs < 1:
        print("error: --runs must be >= 1", file=sys.stderr)
        return 2

    result = run_validation(
        pkg,
        cfg,
        paths,
        runs=args.runs,
        aa_control=args.aa_control,
        capture_logs=not args.no_logs,
    )
    validation = result["validation"]

    if args.json:
        print(json.dumps(validation, indent=2, default=str))
    else:
        print(f"{pkg.cve}: {validation['verdict']}")
        print(f"  reason: {validation['reason']}")
        for role in ("vulnerable", "patched"):
            summary = validation["targets"][role]["summary"]
            print(
                f"  {role:<10} median={summary['median']:.2f} "
                f"min={summary['min']:.2f} max={summary['max']:.2f} "
                f"cv={summary['cv']:.2%} n={summary['count']}"
            )
        ratio = validation["aggregates"].get("ratio")
        if ratio is not None:
            print(f"  relative reduction: {ratio:.2f}x")
        print(f"  evidence: {result['execution_path']}")
        print(f"  validation: {result['validation_path']}")
        print("  package status updated by the validator")

    return 0 if validation["verdict"] == "CONFIRMED" else 1
