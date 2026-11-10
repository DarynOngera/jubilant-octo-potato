"""Argument parser for the VulnForge CLI."""
from __future__ import annotations

import argparse

from .. import __version__
from .admin import _cmd_clean, _cmd_doctor
from .detect_report import _cmd_detect, _cmd_report
from .intel import _cmd_analyze, _cmd_ingest, _cmd_triage
from .lab import _cmd_lab, _cmd_poc
from .package import (
    _cmd_package_list,
    _cmd_package_scaffold,
    _cmd_package_show,
    _cmd_package_validate,
    _cmd_status,
)
from .ui import _cmd_ui
from .validate import _cmd_validate


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

    package_scaffold = package_sub.add_parser(
        "scaffold",
        help="create a draft package from the global advisory catalog",
    )
    package_scaffold.add_argument("cve", help="CVE identifier")
    package_scaffold.add_argument(
        "--target", default="bandit", help="target adapter name (default: bandit)"
    )
    package_scaffold.add_argument(
        "--vulnerable", help="last vulnerable version (default: derive from catalog)"
    )
    package_scaffold.add_argument(
        "--patched", help="first fixed version (default: derive from catalog)"
    )
    package_scaffold.add_argument(
        "--force", action="store_true", help="overwrite scaffolded files"
    )
    package_scaffold.set_defaults(func=_cmd_package_scaffold)

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

    lab_observe = lab_sub.add_parser(
        "observe", help="sample host-side container resources for a running lab"
    )
    lab_observe.add_argument("cve", help="CVE identifier")
    lab_observe.add_argument(
        "--samples", type=int, default=5, help="number of snapshots to collect (default: 5)"
    )
    lab_observe.add_argument(
        "--interval", type=float, default=1.0, help="seconds between snapshots (default: 1)"
    )
    lab_observe.add_argument("--json", action="store_true", help="emit JSON")
    lab_observe.set_defaults(func=_cmd_lab)

    poc = subparsers.add_parser("poc", help="run a package PoC against its runtime")
    poc_sub = poc.add_subparsers(dest="poc_command", required=True)
    poc_build = poc_sub.add_parser(
        "build", help="build a bounded package PoC directly from CVE metadata"
    )
    poc_build.add_argument("cve", help="CVE identifier")
    poc_build.add_argument(
        "--force",
        action="store_true",
        help="replace a generated probe that no longer matches its profile",
    )
    poc_build.set_defaults(func=_cmd_poc)
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
    ingest.add_argument(
        "target",
        nargs="?",
        default="bandit",
        help="target adapter name from config/vulnforge.yaml (default: bandit)",
    )
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

    ui = subparsers.add_parser(
        "ui", help="serve the local read/write dashboard on loopback"
    )
    ui.add_argument(
        "--host", default="127.0.0.1", help="loopback host (default 127.0.0.1)"
    )
    ui.add_argument(
        "--port", type=int, default=0, help="port (default: choose a free port)"
    )
    ui.add_argument("--no-open", action="store_true", help="do not open a browser")
    ui.add_argument(
        "--read-only", action="store_true", help="disable action buttons and POSTs"
    )
    ui.set_defaults(func=_cmd_ui)

    return parser
