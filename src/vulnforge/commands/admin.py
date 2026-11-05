"""Doctor and runtime cleanup CLI commands."""
from __future__ import annotations

import argparse
import json

from ..config import FactoryConfig
from ..doctor import clean_runtime, run_doctor
from ..paths import Paths


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
