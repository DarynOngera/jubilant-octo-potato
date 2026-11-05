"""VulnForge CLI (M1 surface).

Implemented now:
  vulnforge status
  vulnforge package list|show|validate

The remaining factory commands are deliberately stubs until their milestone:
  ingest (M5), triage (M2), lab (M2), poc (M3), validate (M3),
  detect (M4), report (M4)
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .config import FactoryConfig, load_config
from .errors import ConfigError, PackageError, SchemaError
from .models import Package
from .packages import find_package, load_packages, validate_package
from .paths import Paths, find_repo_root


def _package_row(pkg: Package) -> list[str]:
    manifest = pkg.manifest
    if manifest is None:
        return [pkg.cve, "-", "invalid", "-", "-"]
    return [
        manifest.cve,
        manifest.target,
        manifest.status,
        f"{manifest.vulnerable_version} -> {manifest.patched_version}",
        manifest.last_verdict,
    ]


def _print_table(headers: list[str], rows: list[list[str]]) -> None:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    print("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))


def _json_package(pkg: Package) -> dict[str, Any]:
    return {
        "cve": pkg.cve,
        "root": str(pkg.root),
        "manifest": dataclasses.asdict(pkg.manifest) if pkg.manifest else None,
        "advisory": dataclasses.asdict(pkg.advisory) if pkg.advisory else None,
        "lab": dataclasses.asdict(pkg.lab) if pkg.lab else None,
        "probe": dataclasses.asdict(pkg.probe) if pkg.probe else None,
        "errors": pkg.errors,
    }


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
                ["CVE", "Target", "Status", "Versions", "Verdict"],
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
        print(f"  target: {manifest.target}")
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


def _planned(name: str, milestone: str):
    def handler(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
        print(
            f"{name}: not implemented in the M1 factory skeleton; "
            f"planned for {milestone}. See docs/vulnforge-architecture.md.",
            file=sys.stderr,
        )
        return 2

    return handler


def _add_planned(subparsers, name: str, milestone: str, help_text: str) -> None:
    parser = subparsers.add_parser(name, help=help_text)
    parser.add_argument("cve", nargs="?", help="CVE identifier")
    parser.set_defaults(func=_planned(name, milestone))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnforge",
        description="Turn vulnerability intelligence into reproducible labs, PoCs, evidence, detection, and reports.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"vulnforge {__version__}",
    )
    parser.add_argument(
        "--root",
        help="VulnForge workspace root (defaults to the repo containing pyproject.toml)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    status = subparsers.add_parser("status", help="show package status")
    status.add_argument("--json", action="store_true", help="emit JSON")
    status.set_defaults(func=_cmd_status)

    package = subparsers.add_parser("package", help="inspect and validate packages")
    package_sub = package.add_subparsers(dest="package_command", required=True)

    package_list = package_sub.add_parser("list", help="list packages")
    package_list.add_argument("--json", action="store_true", help="emit JSON")
    package_list.set_defaults(func=_cmd_package_list)

    package_show = package_sub.add_parser("show", help="show one package")
    package_show.add_argument("cve", help="CVE identifier, e.g. CVE-2026-116078")
    package_show.add_argument("--json", action="store_true", help="emit JSON")
    package_show.set_defaults(func=_cmd_package_show)

    package_validate = package_sub.add_parser(
        "validate", help="validate one package (or all)"
    )
    package_validate.add_argument("cve", nargs="?", help="CVE identifier")
    package_validate.add_argument(
        "--all", action="store_true", help="validate every discovered package"
    )
    package_validate.add_argument("--json", action="store_true", help="emit JSON")
    package_validate.set_defaults(func=_cmd_package_validate)

    _add_planned(subparsers, "ingest", "M5", "ingest advisory intelligence (M5)")
    _add_planned(subparsers, "triage", "M2", "recompute versions and priorities (M2)")
    _add_planned(subparsers, "lab", "M2", "build/start/stop lab targets (M2)")
    _add_planned(subparsers, "poc", "M3", "run a package PoC (M3)")
    _add_planned(subparsers, "validate", "M3", "run the A/B validation harness (M3)")
    _add_planned(subparsers, "detect", "M4", "run detection rules (M4)")
    _add_planned(subparsers, "report", "M4", "render package/global reports (M4)")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        root = Path(args.root).expanduser().resolve() if args.root else find_repo_root()
        cfg = load_config(root)
        paths = cfg.paths()
        return int(args.func(args, cfg, paths))
    except (ConfigError, PackageError, SchemaError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
