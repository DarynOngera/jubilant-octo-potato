"""Multi-run A/B validation and evidence bundling."""
from __future__ import annotations

import hashlib
import json
import uuid
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ..config import FactoryConfig
from ..errors import LabError
from ..lab import LabRuntime, docker
from ..lab.telemetry import ContainerSampler
from ..models import Package
from ..paths import Paths
from ..probe import ProbeResult, ProbeTarget, load_probe
from ..targets.loader import load_adapter
from .stats import json_safe_number, summarize

ROLES = ("vulnerable", "patched")


def load_runtime(paths: Paths, cve: str) -> tuple[LabRuntime, Path]:
    path = paths.root / ".vulnforge" / "labs" / cve / "runtime.json"
    if not path.exists():
        raise LabError(
            f"no runtime for {cve} at {path}. Run "
            f"`vulnforge lab start {cve}` first."
        )
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise LabError(f"invalid runtime file {path}: {exc}") from exc
    return LabRuntime.from_dict(data), path


def decide_verdict(
    vuln_values: list[float],
    patched_values: list[float],
    thresholds: dict[str, Any],
) -> dict[str, Any]:
    """Pure verdict function so the decision logic is testable without Docker."""
    vuln = summarize(vuln_values)
    patched = summarize(patched_values)
    mode = str(thresholds.get("mode", "absolute"))
    min_samples = int(thresholds.get("min_samples", 1))
    max_cv = float(thresholds.get("max_cv", 1.0))
    warnings: list[str] = []

    base = {
        "mode": mode,
        "vulnerable": vuln.to_dict(),
        "patched": patched.to_dict(),
        "warnings": warnings,
        "ratio": None,
    }

    if vuln.count < min_samples or patched.count < min_samples:
        return {
            **base,
            "verdict": "INCONCLUSIVE",
            "reason": (
                f"need >= {min_samples} successful runs per target; "
                f"got vulnerable={vuln.count}, patched={patched.count}"
            ),
        }

    if patched.cv > max_cv:
        return {
            **base,
            "verdict": "INCONCLUSIVE",
            "reason": (
                f"patched coefficient of variation {patched.cv:.2%} exceeds "
                f"the {max_cv:.2%} guard"
            ),
        }

    if mode == "relative":
        vuln_min = float(thresholds["vulnerable_min"])
        patched_max = float(thresholds["patched_max"])
        min_ratio = float(thresholds.get("min_ratio", 2.0))
        if vuln.median < vuln_min:
            return {
                **base,
                "verdict": "INCONCLUSIVE",
                "reason": (
                    f"vulnerable median {vuln.median:.0f} is below the "
                    f"{vuln_min:.0f} sanity floor"
                ),
            }
        if patched.median <= 0:
            return {
                **base,
                "verdict": "INCONCLUSIVE",
                "reason": "patched median is zero; cannot compute a reduction ratio",
            }
        ratio = vuln.median / patched.median
        base["ratio"] = ratio
        if patched.median > patched_max:
            return {
                **base,
                "verdict": "FAIL",
                "reason": (
                    f"patched median {patched.median:.0f} exceeds the "
                    f"{patched_max:.0f} sanity cap"
                ),
            }
        if ratio < min_ratio:
            return {
                **base,
                "verdict": "INCONCLUSIVE",
                "reason": (
                    f"relative reduction {ratio:.2f}x is below the "
                    f"pre-registered {min_ratio:.2f}x threshold"
                ),
            }
        return {
            **base,
            "verdict": "CONFIRMED",
            "reason": (
                f"vulnerable/patched median memory ratio {ratio:.2f}x "
                f">= {min_ratio:.2f}x"
            ),
        }

    # absolute mode
    vuln_min = float(thresholds["vulnerable_min"])
    patched_max = float(thresholds["patched_max"])
    if vuln.median < vuln_min:
        return {
            **base,
            "verdict": "INCONCLUSIVE",
            "reason": (
                f"vulnerable median {vuln.median:.2f} is below the "
                f"{vuln_min:.2f} minimum"
            ),
        }
    if patched.median > patched_max:
        return {
            **base,
            "verdict": "FAIL",
            "reason": (
                f"patched median {patched.median:.2f} is above the "
                f"{patched_max:.2f} maximum"
            ),
        }
    if vuln.minimum <= patched.maximum:
        return {
            **base,
            "verdict": "INCONCLUSIVE",
            "reason": (
                f"run ranges overlap (vulnerable min {vuln.minimum:.2f}, "
                f"patched max {patched.maximum:.2f})"
            ),
        }
    if vuln.cv > 0.5:
        warnings.append(
            f"vulnerable coefficient of variation is high ({vuln.cv:.2%}); "
            "the separation, not the mean, carries the verdict"
        )
    return {
        **base,
        "verdict": "CONFIRMED",
        "reason": (
            f"vulnerable median {vuln.median:.2f} >= {vuln_min:.2f} and "
            f"patched median {patched.median:.2f} <= {patched_max:.2f}; "
            "run ranges do not overlap"
        ),
    }


def _json_safe(value: Any) -> Any:
    if isinstance(value, float):
        return json_safe_number(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_json_safe(data), indent=2) + "\n")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _image_digests(package: Package, runtime: LabRuntime) -> dict[str, Any]:
    provenance_path = package.root / "lab" / "provenance.json"
    if provenance_path.exists():
        try:
            data = json.loads(provenance_path.read_text())
            return {
                role: {"id": image.get("id"), "tag": image.get("tag")}
                for role, image in data.get("images", {}).items()
            }
        except json.JSONDecodeError:
            pass
    digests: dict[str, Any] = {}
    for role, service in runtime.services.items():
        try:
            image = docker.image_inspect(service.image_tag)
            digests[role] = {"id": image.get("Id"), "tag": service.image_tag}
        except Exception:
            digests[role] = {"id": None, "tag": service.image_tag}
    return digests


def _capture_logs(
    package: Package, runtime: LabRuntime, evidence_dir: Path
) -> list[Path]:
    paths: list[Path] = []
    logs_dir = evidence_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    for role, service in runtime.services.items():
        try:
            result = docker.run(
                ["docker", "logs", "--tail", "200", service.container_name],
                check=False,
            )
            text = (result.stdout or "") + (result.stderr or "")
        except Exception as exc:  # noqa: BLE001 - logs are best-effort
            text = f"could not capture logs: {exc}\n"
        path = logs_dir / f"{role}.log"
        path.write_text(text)
        paths.append(path)
    return paths


def _artifact_entries(package: Package, evidence_dir: Path) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for path in sorted(evidence_dir.rglob("*")):
        if not path.is_file():
            continue
        # execution.json cannot hash itself; README.md is documentation, not
        # evidence, and may be edited without invalidating a run.
        if path.name in ("execution.json", "README.md"):
            continue
        entries.append(
            {
                "path": str(path.relative_to(package.root)),
                "sha256": _sha256(path),
            }
        )
    return entries


def refresh_execution_manifest(package: Package) -> Path:
    """Recompute artifact hashes without re-running the probe."""
    evidence_dir = package.root / "evidence"
    path = evidence_dir / "execution.json"
    data = json.loads(path.read_text())
    data["artifacts"] = _artifact_entries(package, evidence_dir)
    _write_json(path, data)
    return path


def _update_manifest(
    package: Package,
    verdict: str,
    reason: str,
    finished_at: str,
) -> None:
    path = package.root / "package.json"
    data = json.loads(path.read_text())
    status_map = {
        "CONFIRMED": "validated",
        "INCONCLUSIVE": "inconclusive",
        "FAIL": "poc-implemented",
        "ERROR": "poc-implemented",
    }
    data["status"] = status_map.get(verdict, data.get("status", "poc-implemented"))
    validation = dict(data.get("validation", {}))
    validation["last_verdict"] = verdict
    validation["last_run_at"] = finished_at
    validation["evidence"] = "evidence/execution.json"
    validation["notes"] = reason
    data["validation"] = validation
    path.write_text(json.dumps(data, indent=2) + "\n")


def run_validation(
    package: Package,
    cfg: FactoryConfig,
    paths: Paths,
    *,
    probe: Callable[..., Any] | None = None,
    runtime: LabRuntime | None = None,
    runs: int | None = None,
    aa_control: bool = False,
    capture_logs: bool = True,
    capture_host_telemetry: bool = True,
) -> dict[str, Any]:
    if package.manifest is None or package.lab is None or package.probe is None:
        raise LabError(f"package {package.cve} is not complete enough to validate")

    manifest = package.manifest
    probe_manifest = package.probe
    if runtime is None:
        runtime, runtime_path = load_runtime(paths, package.cve)
    else:
        runtime_path = paths.root / ".vulnforge" / "labs" / package.cve / "runtime.json"

    if probe is None:
        probe = load_probe(package.root, probe_manifest)

    adapter = load_adapter(cfg, manifest.adapter_name)
    measurement = adapter.measurement()
    run_count = int(runs or probe_manifest.runs or 1)
    thresholds = dict(probe_manifest.thresholds)
    metric_name = probe_manifest.metric
    kwargs = dict(probe_manifest.kwargs)

    targets: dict[str, ProbeTarget] = {}
    for role in ROLES:
        service = runtime.services.get(role)
        if service is None:
            raise LabError(f"runtime for {package.cve} has no {role!r} service")
        expected = probe_manifest.targets.get(role)
        if expected and expected != service.name:
            raise LabError(
                f"runtime {role} target is {service.name!r}, probe manifest "
                f"expects {expected!r}"
            )
        targets[role] = ProbeTarget.from_service(service, measurement=measurement)

    evidence_dir = package.root / manifest.paths.get("evidence", "evidence")
    runs_dir = evidence_dir / "runs"
    telemetry_dir = evidence_dir / "telemetry"
    runs_dir.mkdir(parents=True, exist_ok=True)
    telemetry_dir.mkdir(parents=True, exist_ok=True)

    started_at = datetime.now(timezone.utc).isoformat()
    validation_id = uuid.uuid4().hex
    records: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    aa_ratios: list[float] = []

    for run_index in range(1, run_count + 1):
        run_metrics: dict[str, float] = {}
        for role in ROLES:
            target = targets[role]
            try:
                run_started_at = datetime.now(timezone.utc).isoformat()
                sampler = (
                    ContainerSampler(runtime.services)
                    if capture_host_telemetry
                    else nullcontext(None)
                )
                with sampler as host_sampler:
                    result = ProbeResult.coerce(probe(target, **kwargs))
                run_finished_at = datetime.now(timezone.utc).isoformat()
                metric = result.metrics.get(metric_name)
                if metric is None:
                    raise LabError(
                        f"probe did not return metric {metric_name!r}; "
                        f"metrics={sorted(result.metrics)}"
                    )
                run_metrics[role] = float(metric)
                record = {
                    "schema_version": "1.0",
                    "validation_id": validation_id,
                    "run": run_index,
                    "role": role,
                    "target": target.name,
                    "version": runtime.services[role].version,
                    "image": runtime.services[role].image_tag,
                    "started_at": run_started_at,
                    "finished_at": run_finished_at,
                    "metric_name": metric_name,
                    "metric": float(metric),
                    "metrics": result.metrics,
                    "duration_s": result.duration_s,
                    "sample_count": result.sample_count,
                    "errors": list(result.errors),
                    "observations": result.observations,
                    "raw": result.raw,
                }
                records.append(record)
                _write_json(runs_dir / f"run-{run_index:02d}-{role}.json", record)
                telemetry = result.observations.get("telemetry")
                host_telemetry = (
                    host_sampler.for_role(role)
                    if isinstance(host_sampler, ContainerSampler)
                    else {"source": "disabled", "samples": [], "errors": []}
                )
                _write_json(
                    telemetry_dir / f"run-{run_index:02d}-{role}.json",
                    {
                        "schema_version": "1.0",
                        "validation_id": validation_id,
                        "cve": package.cve,
                        "run": run_index,
                        "role": role,
                        "target": target.name,
                        "version": runtime.services[role].version,
                        "image": runtime.services[role].image_tag,
                        "started_at": run_started_at,
                        "finished_at": run_finished_at,
                        "telemetry": telemetry if isinstance(telemetry, dict) else {},
                        "host_telemetry": host_telemetry,
                    },
                )
            except Exception as exc:  # noqa: BLE001 - evidence must survive probe errors
                errors.append(
                    {"run": run_index, "role": role, "error": str(exc)}
                )

        if aa_control and "vulnerable" in run_metrics:
            try:
                second = ProbeResult.coerce(probe(targets["vulnerable"], **kwargs))
                second_metric = second.metrics.get(metric_name)
                if second_metric and run_metrics["vulnerable"]:
                    aa_ratios.append(
                        float(second_metric) / float(run_metrics["vulnerable"])
                    )
            except Exception as exc:  # noqa: BLE001
                errors.append(
                    {"run": run_index, "role": "vulnerable-aa", "error": str(exc)}
                )

    finished_at = datetime.now(timezone.utc).isoformat()

    vuln_values = [
        record["metric"]
        for record in records
        if record["role"] == "vulnerable" and "metric" in record
    ]
    patched_values = [
        record["metric"]
        for record in records
        if record["role"] == "patched" and "metric" in record
    ]

    if errors:
        decision = {
            "verdict": "ERROR",
            "reason": f"{len(errors)} probe run(s) failed; see evidence/runs",
            "mode": thresholds.get("mode", "absolute"),
            "vulnerable": summarize(vuln_values).to_dict(),
            "patched": summarize(patched_values).to_dict(),
            "warnings": [],
            "ratio": None,
        }
    else:
        decision = decide_verdict(vuln_values, patched_values, thresholds)

    image_digests = _image_digests(package, runtime)
    logs = _capture_logs(package, runtime, evidence_dir) if capture_logs else []

    validation = {
        "schema_version": "1.0",
        "cve": package.cve,
        "verdict": decision["verdict"],
        "reason": decision["reason"],
        "runs": run_count,
        "validation_id": validation_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "targets": {
            role: {
                "name": runtime.services[role].name,
                "version": runtime.services[role].version,
                "metrics": [
                    json_safe_number(value) for value in (
                        vuln_values if role == "vulnerable" else patched_values
                    )
                ],
                "summary": (
                    decision["vulnerable"]
                    if role == "vulnerable"
                    else decision["patched"]
                ),
            }
            for role in ROLES
        },
        "aggregates": {
            "metric": metric_name,
            "mode": decision.get("mode"),
            "ratio": json_safe_number(decision.get("ratio"))
            if decision.get("ratio") is not None
            else None,
            "thresholds": thresholds,
            "warnings": decision.get("warnings", []),
            "aa_control": {
                "enabled": aa_control,
                "ratios": [json_safe_number(value) for value in aa_ratios],
                "median": json_safe_number(
                    summarize(aa_ratios).median if aa_ratios else 0.0
                ),
            },
            "probe_errors": errors,
        },
        "image_digests": image_digests,
        "evidence_manifest": "evidence/execution.json",
    }
    validation_path = evidence_dir / "validation.json"
    _write_json(validation_path, validation)

    execution = {
        "schema_version": "1.0",
        "cve": package.cve,
        "created_at": finished_at,
        "command": [
            "vulnforge",
            "validate",
            package.cve,
            "--runs",
            str(run_count),
        ],
        "verdict": decision["verdict"],
        "environment": {
            "target": manifest.adapter_name,
            "lab_id": runtime.lab_id,
            "runtime": str(runtime_path),
            "vulnerable_version": runtime.services["vulnerable"].version,
            "patched_version": runtime.services["patched"].version,
            "aa_control": aa_control,
        },
        "images": image_digests,
        "artifacts": [],
    }
    execution_path = evidence_dir / "execution.json"
    execution["artifacts"] = _artifact_entries(package, evidence_dir)
    _write_json(execution_path, execution)

    _update_manifest(
        package,
        decision["verdict"],
        decision["reason"],
        finished_at,
    )

    return {
        "validation": validation,
        "validation_path": validation_path,
        "execution_path": execution_path,
        "logs": logs,
    }
