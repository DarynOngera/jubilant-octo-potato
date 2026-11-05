"""Ingestion, source analysis, and triage CLI commands."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..config import FactoryConfig
from ..errors import PackageError
from ..ingest import IngestError, analyze_package, ingest_target
from ..packages import find_package
from ..paths import Paths
from ..targets.loader import load_adapter
from ..triage import run_triage


def _cmd_ingest(args: argparse.Namespace, cfg: FactoryConfig, paths: Paths) -> int:
    try:
        adapter = load_adapter(cfg, args.target)
        result = ingest_target(
            paths,
            adapter.intelligence(),
            offline=args.offline,
            apply=args.apply,
            raw_path=Path(args.raw).expanduser() if args.raw else None,
        )
    except IngestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
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
    if pkg.manifest is None:
        print(f"error: {pkg.cve} has no package manifest", file=sys.stderr)
        return 1
    adapter = load_adapter(cfg, pkg.manifest.adapter_name)
    intelligence = adapter.intelligence()
    if not intelligence.github_repo:
        print(
            f"error: adapter {pkg.manifest.adapter_name!r} has no GitHub repo; "
            "source analysis is unavailable for this target",
            file=sys.stderr,
        )
        return 1
    result = analyze_package(
        pkg, refresh=args.refresh, repo=intelligence.github_repo
    )
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
