"""Allowlisted background actions for the VulnForge UI.

The UI never builds shell strings. Every action maps to a fixed argv template,
and a single worker runs one job at a time so two actions cannot drive Docker or
the same evidence tree concurrently.
"""
from __future__ import annotations

import queue
import secrets
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from ..config import FactoryConfig
from ..paths import Paths

MAX_LOG_LINES = 2000


@dataclass(frozen=True)
class ActionSpec:
    id: str
    label: str
    description: str
    category: str
    cve_required: bool = False
    cve_allowed: bool = True
    cve_source: str = "packages"
    requires_docker: bool = False
    destructive: bool = False
    confirm: str | None = None
    writes: tuple[str, ...] = ()
    options: dict[str, dict[str, Any]] = field(default_factory=dict)


ACTIONS: dict[str, ActionSpec] = {
    "ingest": ActionSpec(
        id="ingest",
        label="Ingest intelligence",
        description="Fetch/normalize OSV advisories and propose a catalog diff.",
        category="intelligence",
        cve_allowed=False,
        destructive=True,
        confirm="Apply rewrites data/advisories.json. Leave apply unchecked for a dry-run proposal.",
        writes=("data/raw/osv/", "data/proposed/", "data/advisories.json (with apply)"),
        options={
            "target": {
                "type": "enum",
                "choices_from": "targets",
                "choices": [],
                "default": "bandit",
                "label": "Target",
            },
            "refresh": {
                "type": "bool",
                "default": False,
                "label": "Refresh from network",
            },
            "offline": {
                "type": "bool",
                "default": False,
                "label": "Use an offline snapshot",
            },
            "raw": {
                "type": "text",
                "default": "",
                "label": "Snapshot path (with offline)",
            },
            "apply": {
                "type": "bool",
                "default": False,
                "label": "Apply the merged catalog",
            },
        },
    ),
    "analyze": ActionSpec(
        id="analyze",
        label="Analyze commits",
        description="Capture fixing-commit patches and regenerate the root-cause scaffold.",
        category="intelligence",
        cve_required=True,
        writes=("analysis/commits/", "analysis/root-cause.generated.md"),
        options={
            "refresh": {
                "type": "bool",
                "default": False,
                "label": "Refresh cached patches from network",
            }
        },
    ),
    "triage_run": ActionSpec(
        id="triage_run",
        label="Regenerate triage",
        description="Regenerate version exposure, checkpoints, priority matrix, and CSV.",
        category="intelligence",
        cve_allowed=False,
        destructive=True,
        confirm="This rewrites the generated triage artifacts and may rewrite the catalog with --from-packages.",
        writes=(
            "data/version-cve-map.json",
            "data/lab-checkpoints.json",
            "data/vulnerability-matrix.json",
            "reports/vulnerability-matrix.csv",
            "data/advisories.json (with --from-packages)",
        ),
        options={
            "from_packages": {
                "type": "bool",
                "default": False,
                "label": "Overlay packaged advisories first",
            }
        },
    ),
    "doctor": ActionSpec(
        id="doctor",
        label="Run doctor",
        description="Check Python, Docker, config, schemas, and packages.",
        category="system",
        cve_allowed=False,
        writes=("no tracked files",),
    ),
    "clean": ActionSpec(
        id="clean",
        label="Clean runtime",
        description="Remove .vulnforge runtime state. Dry-run is the default.",
        category="system",
        cve_allowed=False,
        destructive=True,
        confirm="Without dry-run this removes .vulnforge runtime state, including lab runtime files.",
        writes=(".vulnforge/",),
        options={
            "dry_run": {
                "type": "bool",
                "default": True,
                "label": "Dry run only",
            }
        },
    ),
    "package_scaffold": ActionSpec(
        id="package_scaffold",
        label="Scaffold package",
        description="Create a draft package from a catalog advisory.",
        category="package",
        cve_required=True,
        cve_source="catalog",
        writes=("vulnerabilities/<CVE>/",),
        options={
            "target": {
                "type": "text",
                "default": "bandit",
                "label": "Adapter",
            },
            "vulnerable": {
                "type": "text",
                "default": "",
                "label": "Vulnerable version (optional)",
            },
            "patched": {
                "type": "text",
                "default": "",
                "label": "Patched version (optional)",
            },
            "force": {
                "type": "bool",
                "default": False,
                "label": "Overwrite existing files",
            },
        },
    ),
    "lab_build": ActionSpec(
        id="lab_build",
        label="Build lab",
        description="Build the vulnerable/patched images and refresh provenance.",
        category="lab",
        cve_required=True,
        requires_docker=True,
        writes=("lab/provenance.json",),
    ),
    "lab_start": ActionSpec(
        id="lab_start",
        label="Start lab",
        description="Start the loopback lab containers and record runtime provenance.",
        category="lab",
        cve_required=True,
        requires_docker=True,
        writes=("lab/provenance.json",),
    ),
    "lab_stop": ActionSpec(
        id="lab_stop",
        label="Stop lab",
        description="Stop and remove the lab containers and network.",
        category="lab",
        cve_required=True,
        requires_docker=True,
        destructive=True,
    ),
    "validate": ActionSpec(
        id="validate",
        label="Run validation",
        description="Run the multi-run A/B validation and rewrite evidence.",
        category="evidence",
        cve_required=True,
        requires_docker=True,
        writes=("evidence/", "package.json"),
        options={
            "runs": {
                "type": "int",
                "min": 1,
                "max": 10,
                "default": None,
                "label": "Runs",
                "help": "Blank uses the package manifest value.",
            }
        },
    ),
    "poc_run": ActionSpec(
        id="poc_run",
        label="Run PoC",
        description="Run the package probe once against the running lab.",
        category="evidence",
        cve_required=True,
        requires_docker=True,
        writes=("no tracked files (prints results)",),
        options={
            "role": {
                "type": "enum",
                "choices": ["both", "vulnerable", "patched"],
                "default": "both",
                "label": "Role",
            }
        },
    ),
    "detect": ActionSpec(
        id="detect",
        label="Run detection",
        description="Evaluate the behavioral rules and rewrite detection evidence.",
        category="evidence",
        cve_allowed=True,
        writes=("detection/evidence.json",),
    ),
    "report": ActionSpec(
        id="report",
        label="Generate reports",
        description="Regenerate the per-CVE and global reports.",
        category="evidence",
        cve_allowed=True,
        writes=("report.md", "report.json", "reports/technical-report.md"),
    ),
    "package_validate": ActionSpec(
        id="package_validate",
        label="Validate package",
        description="Check package files, schemas, and catalog consistency.",
        category="health",
        cve_allowed=True,
        writes=("no tracked files",),
    ),
    "triage_check": ActionSpec(
        id="triage_check",
        label="Check triage drift",
        description="Verify generated matrix/checkpoint artifacts are current.",
        category="health",
        cve_allowed=False,
        writes=("no tracked files",),
    ),
}


def build_command(action_id: str, cve: str | None, options: dict[str, Any]) -> list[str]:
    if action_id == "ingest":
        argv = ["ingest", str(options.get("target") or "bandit")]
        if options.get("refresh"):
            argv.append("--refresh")
        if options.get("offline"):
            argv.append("--offline")
        if options.get("raw"):
            argv.extend(["--raw", str(options["raw"])])
        if options.get("apply"):
            argv.append("--apply")
        return argv
    if action_id == "analyze":
        argv = ["analyze", _cve(cve)]
        if options.get("refresh"):
            argv.append("--refresh")
        return argv
    if action_id == "triage_run":
        argv = ["triage"]
        if options.get("from_packages"):
            argv.append("--from-packages")
        return argv
    if action_id == "doctor":
        return ["doctor"]
    if action_id == "clean":
        return ["clean", "--dry-run"] if options.get("dry_run", True) else ["clean"]
    if action_id == "package_scaffold":
        argv = ["package", "scaffold", _cve(cve)]
        target = options.get("target")
        if target:
            argv.extend(["--target", str(target)])
        for key in ("vulnerable", "patched"):
            value = options.get(key)
            if value:
                argv.extend([f"--{key}", str(value)])
        if options.get("force"):
            argv.append("--force")
        return argv
    if action_id == "lab_build":
        return ["lab", "build", _cve(cve)]
    if action_id == "lab_start":
        return ["lab", "start", _cve(cve)]
    if action_id == "lab_stop":
        return ["lab", "stop", _cve(cve)]
    if action_id == "validate":
        argv = ["validate", _cve(cve)]
        runs = options.get("runs")
        if runs not in (None, ""):
            argv.extend(["--runs", str(int(runs))])
        return argv
    if action_id == "poc_run":
        role = options.get("role") or "both"
        return ["poc", "run", _cve(cve), "--role", str(role)]
    if action_id == "detect":
        return ["detect", cve] if cve else ["detect", "--all"]
    if action_id == "report":
        return ["report", cve] if cve else ["report", "--all"]
    if action_id == "package_validate":
        return ["package", "validate", cve] if cve else ["package", "validate", "--all"]
    if action_id == "triage_check":
        return ["triage", "--check"]
    raise ValueError(f"unknown action: {action_id}")


def _cve(cve: str | None) -> str:
    if not cve:
        raise ValueError("this action requires a CVE")
    return cve


def validate_request(
    action_id: str,
    cve: str | None,
    options: dict[str, Any] | None,
    known_cves: set[str],
    known_catalog: set[str] | None = None,
    known_targets: set[str] | None = None,
) -> tuple[ActionSpec, dict[str, Any], list[str]]:
    spec = ACTIONS.get(action_id)
    if spec is None:
        raise ValueError(f"unknown action: {action_id}")

    options = dict(options or {})
    if cve:
        cve = str(cve)
        if spec.cve_source == "catalog":
            allowed = known_catalog if known_catalog is not None else set()
            if cve not in allowed:
                raise ValueError(f"unknown catalog advisory: {cve}")
        elif cve not in known_cves:
            raise ValueError(f"unknown package: {cve}")
    if spec.cve_required and not cve:
        raise ValueError(f"{spec.label} requires a CVE")
    if not spec.cve_allowed and cve:
        raise ValueError(f"{spec.label} does not take a CVE")

    unknown = set(options) - set(spec.options)
    if unknown:
        raise ValueError(f"unknown option(s): {', '.join(sorted(unknown))}")

    for name, meta in spec.options.items():
        value = options.get(name)
        if value in (None, ""):
            options.pop(name, None)
            continue
        if meta["type"] == "int":
            try:
                number = int(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{name} must be an integer") from exc
            if not meta["min"] <= number <= meta["max"]:
                raise ValueError(
                    f"{name} must be between {meta['min']} and {meta['max']}"
                )
            options[name] = number
        elif meta["type"] == "enum":
            choices = (
                sorted(known_targets or set())
                if meta.get("choices_from") == "targets"
                else list(meta.get("choices", []))
            )
            if value not in choices:
                raise ValueError(
                    f"{name} must be one of: {', '.join(choices)}"
                )
            options[name] = value
        elif meta["type"] == "text":
            options[name] = str(value)
        elif meta["type"] == "bool":
            options[name] = bool(value)

    return spec, options, build_command(action_id, cve, options)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class JobManager:
    def __init__(
        self,
        cfg: FactoryConfig,
        paths: Paths,
        *,
        runner: Callable[[list[str], Callable[[str], None]], int] | None = None,
    ):
        self.cfg = cfg
        self.paths = paths
        self._runner = runner or self._run_subprocess
        self._jobs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._queue: queue.Queue[str] = queue.Queue()
        self._worker = threading.Thread(
            target=self._work, name="vulnforge-ui-jobs", daemon=True
        )
        self._worker.start()

    def _run_subprocess(self, argv: list[str], emit: Callable[[str], None]) -> int:
        command = [sys.executable, "-m", "vulnforge", "--root", str(self.cfg.root), *argv]
        emit("$ " + " ".join(command))
        process = subprocess.Popen(
            command,
            cwd=str(self.cfg.root),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert process.stdout is not None
        for line in process.stdout:
            emit(line.rstrip("\n"))
        return int(process.wait())

    def _append(self, job_id: str, line: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job["log"].append(line)
            if len(job["log"]) > MAX_LOG_LINES:
                del job["log"][: len(job["log"]) - MAX_LOG_LINES]
            job["updated_at"] = _now()

    def _work(self) -> None:
        while True:
            job_id = self._queue.get()
            try:
                with self._lock:
                    job = self._jobs.get(job_id)
                    if job is None:
                        continue
                    job["status"] = "running"
                    job["started_at"] = _now()
                    argv = list(job["argv"])
                try:
                    returncode = self._runner(
                        argv, lambda line: self._append(job_id, line)
                    )
                except Exception as exc:  # surface the failure in the log
                    self._append(job_id, f"error: {exc}")
                    returncode = -1
                with self._lock:
                    job = self._jobs.get(job_id)
                    if job is None:
                        continue
                    job["returncode"] = returncode
                    job["status"] = "succeeded" if returncode == 0 else "failed"
                    job["finished_at"] = _now()
            finally:
                self._queue.task_done()

    def submit(
        self,
        action_id: str,
        cve: str | None,
        options: dict[str, Any] | None,
        known_cves: set[str],
        known_catalog: set[str] | None = None,
        known_targets: set[str] | None = None,
    ) -> dict[str, Any]:
        spec, options, argv = validate_request(
            action_id, cve, options, known_cves, known_catalog, known_targets
        )
        job_id = secrets.token_hex(8)
        now = _now()
        record = {
            "id": job_id,
            "action": spec.id,
            "label": spec.label,
            "category": spec.category,
            "cve": cve,
            "options": options,
            "argv": argv,
            "command": "vulnforge " + " ".join(argv),
            "status": "queued",
            "created_at": now,
            "updated_at": now,
            "started_at": None,
            "finished_at": None,
            "returncode": None,
            "log": [],
        }
        with self._lock:
            self._jobs[job_id] = record
        self._queue.put(job_id)
        return self.snapshot(job_id)

    def snapshot(self, job_id: str, *, include_log: bool = True) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise KeyError(job_id)
            data = {key: value for key, value in job.items() if key not in {"argv", "log"}}
            data["argv"] = list(job["argv"])
            data["log"] = list(job["log"]) if include_log else []
            data["last_line"] = job["log"][-1] if job["log"] else ""
            return data

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            ids = sorted(
                self._jobs, key=lambda item: self._jobs[item]["created_at"], reverse=True
            )
        return [self.snapshot(job_id, include_log=False) for job_id in ids]


def actions_payload(
    *,
    known_cves: set[str],
    known_catalog: set[str] | None = None,
    known_targets: set[str] | None = None,
    docker_ok: bool,
    read_only: bool,
) -> list[dict[str, Any]]:
    payload: list[dict[str, Any]] = []
    for spec in ACTIONS.values():
        reason = None
        if read_only:
            reason = "UI is running in read-only mode"
        elif spec.requires_docker and not docker_ok:
            reason = "Docker daemon or Compose is not available"
        available_cves = (
            sorted((known_catalog or set()) - known_cves)
            if spec.cve_source == "catalog"
            else sorted(known_cves) if spec.cve_allowed else []
        )
        payload.append(
            {
                "id": spec.id,
                "label": spec.label,
                "description": spec.description,
                "category": spec.category,
                "cve_required": spec.cve_required,
                "cve_allowed": spec.cve_allowed,
                "cve_source": spec.cve_source,
                "requires_docker": spec.requires_docker,
                "destructive": spec.destructive,
                "writes": list(spec.writes),
                "options": {
                    key: (
                        {
                            **meta,
                            "choices": sorted(known_targets or set()),
                        }
                        if meta.get("choices_from") == "targets"
                        else meta
                    )
                    for key, meta in spec.options.items()
                },
                "confirm": spec.confirm,
                "enabled": reason is None,
                "disabled_reason": reason,
                "known_cves": available_cves,
            }
        )
    return payload
