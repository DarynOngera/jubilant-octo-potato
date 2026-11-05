"""Shared CLI formatting and package helpers."""
from __future__ import annotations

import dataclasses
from typing import Any

from ..models import Package


def _package_row(pkg: Package) -> list[str]:
    manifest = pkg.manifest
    if manifest is None:
        return [pkg.cve, "-", "invalid", "-", "-"]
    return [
        manifest.cve,
        manifest.adapter_name,
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
