"""Package lifecycle CLI commands."""
from __future__ import annotations

import argparse
import json
import sys

from ..config import FactoryConfig
from ..errors import PackageError
from ..packages import find_package, load_packages, validate_package
from ..paths import Paths
from ..scaffold import scaffold_package
from .common import _json_package, _package_row, _print_table


def _cmd_status(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    packages = load_packages(paths)
    if args.json:
        payload = []
        for pkg in packages:
            item = _json_package(pkg)
            item["validation_errors"] = validate_package(pkg, paths)
            item["valid"] = not item["validation_errors"]
            payload.append(item)
        print(json.dumps(payload, indent=2))
    else:
        print(f"VulnForge packages ({len(packages)})")
        if packages:
            _print_table(
                ["CVE", "Adapter", "Status", "Versions", "Verdict"],
                [_package_row(pkg) for pkg in packages],
            )
        else:
            print(f"  no packages found under {paths.packages}")
        invalid = [pkg for pkg in packages if validate_package(pkg, paths)]
        if invalid:
            print(
                f"\n{len(invalid)} package(s) have validation errors; "
                "run `vulnforge package validate` for details.",
                file=sys.stderr,
            )
    return 1 if any(validate_package(pkg, paths) for pkg in packages) else 0


def _cmd_package_list(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    return _cmd_status(args, cfg, paths)


def _cmd_package_show(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    try:
        pkg = find_package(paths, args.cve)
    except PackageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(_json_package(pkg), indent=2))
        return 0 if pkg.is_valid else 1

    manifest = pkg.manifest
    print(pkg.cve)
    print(f"  package: {pkg.root}")
    if manifest is not None:
        print(f"  adapter: {manifest.adapter_name}")
        print(f"  status: {manifest.status}")
        print(
            f"  versions: {manifest.vulnerable_version} (vulnerable) -> "
            f"{manifest.patched_version} (patched); first fixed "
            f"{manifest.first_fixed}"
        )
        print(f"  verdict: {manifest.last_verdict}")
        print(f"  advisory: {manifest.paths.get('advisory')}")
        print(f"  lab: {manifest.paths.get('lab')}")
        print(f"  poc: {manifest.paths.get('poc')}")
        print(f"  evidence: {manifest.validation.get('evidence', manifest.paths.get('evidence'))}")
    if pkg.lab is not None:
        print("  lab targets:")
        for target in pkg.lab.targets:
            print(
                f"    - {target.role:<10} {target.name:<10} "
                f"{target.version:<10} {target.base_url} "
                f"(admin {target.admin_url})"
            )
    if pkg.probe is not None:
        print(
            f"  probe: {pkg.probe.entrypoint} "
            f"({pkg.probe.metric}; vulnerable >= "
            f"{pkg.probe.thresholds.get('vulnerable_min')}x, patched <= "
            f"{pkg.probe.thresholds.get('patched_max')}x)"
        )
    errors = validate_package(pkg, paths)
    if errors:
        print("\n  validation errors:")
        for error in errors:
            print(f"    - {error}")
        return 1
    return 0


def _cmd_package_validate(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    if args.all and args.cve:
        print("error: pass either a CVE or --all, not both", file=sys.stderr)
        return 2
    try:
        packages = (
            [find_package(paths, args.cve)]
            if args.cve
            else load_packages(paths)
        )
    except PackageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    results = []
    for pkg in packages:
        errors = validate_package(pkg, paths)
        results.append({"cve": pkg.cve, "ok": not errors, "errors": errors})

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            if result["ok"]:
                print(f"OK   {result['cve']}")
            else:
                print(f"FAIL {result['cve']}")
                for error in result["errors"]:
                    print(f"     - {error}")
        if not results:
            print(f"no packages found under {paths.packages}")

    return 0 if all(result["ok"] for result in results) else 1


def _cmd_package_scaffold(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    try:
        created = scaffold_package(
            cfg,
            paths,
            args.cve,
            target=args.target,
            vulnerable=args.vulnerable,
            patched=args.patched,
            force=args.force,
        )
    except PackageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Scaffolded draft package for {args.cve}")
    for path in created:
        print(f"  {path}")
    print("Next: implement poc/exploit.py, set the predicate in poc/manifest.json,")
    print("      then run `vulnforge package validate`, `lab start`, and `validate`.")
    return 0
