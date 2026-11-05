"""Lab and single-run probe CLI commands."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from ..config import FactoryConfig
from ..errors import PackageError
from ..lab import LabOrchestrator
from ..packages import find_package, validate_package
from ..paths import Paths
from ..probe import ProbeResult, ProbeTarget, load_probe
from ..targets.loader import load_adapter
from ..validate import load_runtime
from .common import _print_table


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

    adapter = load_adapter(cfg, manifest.adapter_name)
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
    adapter = load_adapter(cfg, pkg.manifest.adapter_name)
    measurement = adapter.measurement()
    roles = ["vulnerable", "patched"] if args.role == "both" else [args.role]
    records: list[dict[str, Any]] = []
    for role in roles:
        service = runtime.services.get(role)
        if service is None:
            print(f"error: runtime has no {role!r} service", file=sys.stderr)
            return 1
        target = ProbeTarget.from_service(service, measurement=measurement)
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
