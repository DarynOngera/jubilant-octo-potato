"""Detection and report CLI commands."""
from __future__ import annotations

import argparse
import json
import sys

from ..config import FactoryConfig
from ..detect import run_detection
from ..errors import PackageError
from ..packages import find_package, load_packages, validate_package
from ..paths import Paths
from ..report import generate_global_report, write_package_report


def _cmd_detect(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    try:
        packages = (
            [find_package(paths, args.cve, enforce_status_artifacts=False)]
            if args.cve
            else load_packages(paths, enforce_status_artifacts=False)
        )
    except PackageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    results = []
    for pkg in packages:
        errors = validate_package(pkg, paths)
        if errors:
            print(f"package {pkg.cve} is invalid:", file=sys.stderr)
            for error in errors:
                print(f"  - {error}", file=sys.stderr)
            return 1
        result = run_detection(pkg)
        results.append(result)
        if not args.json:
            print(f"{pkg.cve}: {result['result']} -- {result['reason']}")
            for role, target in result["targets"].items():
                print(f"  {role:<10} {target['result']} (bandit {target['version']})")
                for rule in target["rules"]:
                    flag = "TRIGGERED" if rule["triggered"] else "ok"
                    print(f"    [{flag:>10}] {rule['id']}: {rule['detail']}")

    if args.json:
        print(json.dumps(results, indent=2))
    return (
        0
        if all(result["result"] in {"TRIGGERED", "INCONCLUSIVE"} for result in results)
        else 1
    )


def _cmd_report(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    if args.all and args.cve:
        print("error: pass either a CVE or --all, not both", file=sys.stderr)
        return 2
    try:
        packages = (
            [find_package(paths, args.cve, enforce_status_artifacts=False)]
            if args.cve
            else load_packages(paths, enforce_status_artifacts=False)
        )
    except PackageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    outputs = []
    for pkg in packages:
        errors = validate_package(pkg, paths)
        if errors:
            print(f"package {pkg.cve} is invalid:", file=sys.stderr)
            for error in errors:
                print(f"  - {error}", file=sys.stderr)
            return 1
        report_path, json_path = write_package_report(pkg)
        outputs.append(
            {
                "cve": pkg.cve,
                "report": str(report_path),
                "json": str(json_path),
            }
        )
        if not args.json:
            print(f"Wrote {report_path}")
            print(f"Wrote {json_path}")

    global_path = None
    if args.all or not args.cve:
        global_path = generate_global_report(paths)
        if not args.json:
            print(f"Wrote {global_path}")

    if args.json:
        print(
            json.dumps(
                {"packages": outputs, "global": str(global_path) if global_path else None},
                indent=2,
            )
        )
    return 0
