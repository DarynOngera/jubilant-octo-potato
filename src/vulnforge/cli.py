"""VulnForge CLI.

Implemented:
  status, package list|show|validate, lab build|start|stop|status,
  poc run, validate, detect, report, ingest, analyze, triage
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
from .detect import run_detection
from .doctor import clean_runtime, run_doctor
from .errors import PackageError, VulnForgeError
from .ingest import analyze_package, ingest_bandit
from .lab import LabOrchestrator
from .models import Package
from .packages import find_package, load_packages, validate_package
from .paths import Paths, find_repo_root
from .probe import ProbeResult, ProbeTarget, load_probe
from .targets.loader import load_adapter
from .triage import run_triage
from .validate import load_runtime, run_validation


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


def _cmd_lab(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    try:
        pkg = find_package(paths, args.cve)
    except PackageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    errors = validate_package(pkg, paths)
    if errors:
        print(
            f"package {pkg.cve} is invalid; fix it before using the lab:",
            file=sys.stderr,
        )
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    manifest = pkg.manifest
    if manifest is None:
        print(f"error: package {pkg.cve} has no manifest", file=sys.stderr)
        return 1

    adapter = load_adapter(cfg, manifest.target)
    orchestrator = LabOrchestrator(cfg, paths, adapter)

    if args.lab_command == "build":
        plan, provenance_path = orchestrator.build(
            pkg, no_cache=bool(getattr(args, "no_cache", False))
        )
        print(f"Built lab for {pkg.cve}")
        for role, service in plan.services.items():
            print(f"  {role:<10} {service.version:<10} {service.image_tag}")
        print(f"  provenance: {provenance_path}")
        return 0

    if args.lab_command == "start":
        runtime, provenance_path = orchestrator.start(pkg)
        print(f"Started lab for {pkg.cve} ({runtime.lab_id})")
        for role, service in runtime.services.items():
            print(
                f"  {role:<10} {service.name:<10} {service.version:<10} "
                f"{service.base_url} (admin {service.admin_url})"
            )
        print(f"  provenance: {provenance_path}")
        return 0

    if args.lab_command == "stop":
        orchestrator.stop(pkg)
        print(f"Stopped and removed lab for {pkg.cve}")
        return 0

    if args.lab_command == "status":
        status = orchestrator.status(pkg)
        if getattr(args, "json", False):
            print(json.dumps(status, indent=2))
        elif not status.get("running"):
            print(f"{pkg.cve}: not running ({status.get('reason', 'unknown')})")
        else:
            print(f"{pkg.cve}: running ({status.get('lab_id')})")
            _print_table(
                ["Role", "Target", "Version", "Container", "Running", "Healthy", "Reported"],
                [
                    [
                        role,
                        service["name"],
                        service["version"],
                        service["container_name"],
                        "yes" if service["running"] else "no",
                        "yes" if service["healthy"] else "no",
                        str(service["reported_version"] or "-"),
                    ]
                    for role, service in status["services"].items()
                ],
            )
        return 0

    print(f"error: unknown lab command {args.lab_command!r}", file=sys.stderr)
    return 2


def _cmd_poc(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    try:
        pkg = find_package(paths, args.cve)
    except PackageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    errors = validate_package(pkg, paths)
    if errors:
        print(f"package {pkg.cve} is invalid:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    if pkg.manifest is None or pkg.probe is None:
        print(f"error: {pkg.cve} has no probe manifest", file=sys.stderr)
        return 1

    runtime, runtime_path = load_runtime(paths, pkg.cve)
    probe = load_probe(pkg.root, pkg.probe)
    roles = ["vulnerable", "patched"] if args.role == "both" else [args.role]
    records: list[dict[str, Any]] = []
    for role in roles:
        service = runtime.services.get(role)
        if service is None:
            print(f"error: runtime has no {role!r} service", file=sys.stderr)
            return 1
        target = ProbeTarget.from_service(service)
        result = ProbeResult.coerce(probe(target, **pkg.probe.kwargs))
        record = {
            "role": role,
            "target": target.name,
            "version": service.version,
            "metrics": result.metrics,
            "observations": result.observations,
            "duration_s": result.duration_s,
            "sample_count": result.sample_count,
            "errors": result.errors,
            "raw": result.raw,
        }
        records.append(record)
        if not args.json:
            metrics = " ".join(
                f"{key}={value:.4g}" for key, value in result.metrics.items()
            )
            print(
                f"{role:<10} {service.name:<10} {service.version:<10} "
                f"{metrics} samples={result.sample_count}"
            )

    if args.json:
        print(json.dumps(records, indent=2, default=str))
    print(f"  runtime: {runtime_path}")
    return 0


def _cmd_validate(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    try:
        pkg = find_package(paths, args.cve)
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


def _cmd_detect(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
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
    from .report import generate_global_report, write_package_report

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


def _cmd_ingest(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    if args.target != "bandit":
        print(f"error: unsupported ingest target {args.target!r}", file=sys.stderr)
        return 2
    raw_path = Path(args.raw).expanduser() if args.raw else None
    result = ingest_bandit(
        paths,
        offline=args.offline,
        apply=args.apply,
        raw_path=raw_path,
    )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        changes = result["changes"]
        print(f"source: {result['source']}")
        print(f"normalized advisories: {result['normalized']}")
        print(
            f"added: {len(changes['added'])}, changed: "
            f"{len(changes['changed'])}, unchanged: {len(changes['unchanged'])}"
        )
        print(f"proposal: {result['proposed']}")
        print(f"diff: {result['diff']}")
        if result["applied"]:
            print("applied to data/advisories.json")
        else:
            print("dry-run; pass --apply to update data/advisories.json")
    return 0


def _cmd_analyze(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    try:
        pkg = find_package(paths, args.cve)
    except PackageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    result = analyze_package(pkg, refresh=args.refresh)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{pkg.cve}: captured {len(result['commits'])} commit(s)")
        for item in result["commits"]:
            print(f"  {item['commit']} -> {item['patch']}")
        if result["changed_files"]:
            print("  changed files: " + ", ".join(result["changed_files"]))
        for error in result["errors"]:
            print(f"  error {error['commit']}: {error['error']}", file=sys.stderr)
        print(f"  scaffold: {result['scaffold']}")
    return 0 if not result["errors"] else 1


def _cmd_triage(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    result = run_triage(
        paths,
        check=args.check,
        from_packages=args.from_packages,
    )
    if args.json:
        print(json.dumps(result, indent=2))
    elif args.check:
        print(result["stdout"], end="")
        if result["stderr"]:
            print(result["stderr"], end="", file=sys.stderr)
    else:
        if result.get("overlaid"):
            print("overlaid packaged advisories: " + ", ".join(result["overlaid"]))
        print(result["resolver"], end="")
        print(result["prioritizer"], end="")
    return int(result.get("returncode", 0))


def _cmd_doctor(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    checks = run_doctor(paths)
    if args.json:
        print(
            json.dumps(
                [
                    {"name": check.name, "ok": check.ok, "detail": check.detail}
                    for check in checks
                ],
                indent=2,
            )
        )
    else:
        for check in checks:
            flag = "OK" if check.ok else "FAIL"
            print(f"[{flag:>4}] {check.name}: {check.detail}")
    return 0 if all(check.ok for check in checks) else 1


def _cmd_clean(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    removed = clean_runtime(paths, dry_run=args.dry_run)
    if args.json:
        print(json.dumps([str(path) for path in removed], indent=2))
    else:
        for path in removed:
            print(f"{'would remove' if args.dry_run else 'removed'} {path}")
        if not removed:
            print("nothing to clean")
    return 0


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

    lab = subparsers.add_parser("lab", help="build/start/stop/status lab targets")
    lab_sub = lab.add_subparsers(dest="lab_command", required=True)

    lab_build = lab_sub.add_parser("build", help="build vulnerable/patched images")
    lab_build.add_argument("cve", help="CVE identifier")
    lab_build.add_argument("--no-cache", action="store_true", help="disable Docker build cache")
    lab_build.set_defaults(func=_cmd_lab)

    lab_start = lab_sub.add_parser("start", help="start the lab on dynamic loopback ports")
    lab_start.add_argument("cve", help="CVE identifier")
    lab_start.set_defaults(func=_cmd_lab)

    lab_stop = lab_sub.add_parser("stop", help="stop and remove the lab")
    lab_stop.add_argument("cve", help="CVE identifier")
    lab_stop.set_defaults(func=_cmd_lab)

    lab_status = lab_sub.add_parser("status", help="show lab state/health")
    lab_status.add_argument("cve", help="CVE identifier")
    lab_status.add_argument("--json", action="store_true", help="emit JSON")
    lab_status.set_defaults(func=_cmd_lab)

    poc = subparsers.add_parser("poc", help="run a package PoC against its runtime")
    poc_sub = poc.add_subparsers(dest="poc_command", required=True)
    poc_run = poc_sub.add_parser("run", help="run the probe once")
    poc_run.add_argument("cve", help="CVE identifier")
    poc_run.add_argument(
        "--role", choices=["vulnerable", "patched", "both"], default="both"
    )
    poc_run.add_argument("--json", action="store_true", help="emit JSON")
    poc_run.set_defaults(func=_cmd_poc)

    validate = subparsers.add_parser(
        "validate", help="run multi-run A/B validation and write evidence"
    )
    validate.add_argument("cve", help="CVE identifier")
    validate.add_argument(
        "--runs", type=int, default=None, help="override the manifest run count"
    )
    validate.add_argument(
        "--aa-control",
        action="store_true",
        help="run the vulnerable target twice per repetition and record A/A ratios",
    )
    validate.add_argument(
        "--no-logs", action="store_true", help="skip container log capture"
    )
    validate.add_argument("--json", action="store_true", help="emit JSON")
    validate.set_defaults(func=_cmd_validate)

    detect = subparsers.add_parser(
        "detect", help="run behavioral detection over captured evidence"
    )
    detect.add_argument("cve", nargs="?", help="CVE identifier (omit for all)")
    detect.add_argument("--all", action="store_true", help="run every package")
    detect.add_argument("--json", action="store_true", help="emit JSON")
    detect.set_defaults(func=_cmd_detect)

    report = subparsers.add_parser(
        "report", help="generate per-CVE and global reports from evidence"
    )
    report.add_argument("cve", nargs="?", help="CVE identifier (omit for all)")
    report.add_argument("--all", action="store_true", help="generate every package and the global report")
    report.add_argument("--json", action="store_true", help="emit JSON")
    report.set_defaults(func=_cmd_report)

    ingest = subparsers.add_parser(
        "ingest", help="fetch/normalize advisory intelligence and propose a diff"
    )
    ingest.add_argument("target", choices=["bandit"], help="target name")
    ingest.add_argument("--refresh", action="store_true", help="force a network refresh")
    ingest.add_argument("--offline", action="store_true", help="use a cached snapshot")
    ingest.add_argument("--raw", help="path to a cached snapshot (with --offline)")
    ingest.add_argument("--apply", action="store_true", help="write the merged catalog")
    ingest.add_argument("--json", action="store_true", help="emit JSON")
    ingest.set_defaults(func=_cmd_ingest)

    analyze = subparsers.add_parser(
        "analyze", help="capture fixing-commit patches and generate a root-cause scaffold"
    )
    analyze.add_argument("cve", help="CVE identifier")
    analyze.add_argument("--refresh", action="store_true", help="re-fetch cached patches")
    analyze.add_argument("--json", action="store_true", help="emit JSON")
    analyze.set_defaults(func=_cmd_analyze)

    triage = subparsers.add_parser(
        "triage", help="regenerate version exposure/checkpoints and the priority matrix"
    )
    triage.add_argument("--check", action="store_true", help="verify generated artifacts")
    triage.add_argument(
        "--from-packages",
        action="store_true",
        help="overlay packaged advisories onto the global catalog first",
    )
    triage.add_argument("--json", action="store_true", help="emit JSON")
    triage.set_defaults(func=_cmd_triage)

    doctor = subparsers.add_parser(
        "doctor", help="check Python, Docker, config, schemas, and packages"
    )
    doctor.add_argument("--json", action="store_true", help="emit JSON")
    doctor.set_defaults(func=_cmd_doctor)

    clean = subparsers.add_parser(
        "clean", help="remove generated .vulnforge runtime state"
    )
    clean.add_argument("--dry-run", action="store_true", help="show what would be removed")
    clean.add_argument("--json", action="store_true", help="emit JSON")
    clean.set_defaults(func=_cmd_clean)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        root = Path(args.root).expanduser().resolve() if args.root else find_repo_root()
        cfg = load_config(root)
        paths = cfg.paths()
        return int(args.func(args, cfg, paths))
    except VulnForgeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
