"""Offline detection runner over captured validation evidence."""
from __future__ import annotations

import json
from typing import Any

from ..errors import LabError
from ..models import Package
from .rules import DEFAULTS, ConnectionSample, ProcessGrowthSample, evaluate

ROLES = ("vulnerable", "patched")

# Spec threshold names -> rule config names. Both frame and chunk spellings are
# accepted because the packages describe HTTP/2 frames and HTTP/1 chunks.
SPEC_THRESHOLD_KEYS: dict[str, dict[str, str]] = {
    "per_connection_frame_rate": {
        "frames_per_second_min": "max_frame_rate_per_sec",
        "chunks_per_second_min": "max_frame_rate_per_sec",
        "avg_frame_bytes_max": "min_bytes_per_frame_ok",
        "avg_chunk_bytes_max": "min_bytes_per_frame_ok",
    },
    "memory_per_connection_outlier": {
        "stdevs": "memory_outlier_stdevs",
        "min_attack_bytes": "memory_outlier_floor_bytes",
    },
    "body_duration_vs_size": {
        "seconds_per_kb_max": "max_body_duration_per_kb_s",
    },
    "unbounded_process_growth": {
        "min_process_growth": "min_process_growth",
        "min_idle_growth_bytes": "min_idle_growth_bytes",
        "min_samples": "min_process_growth_samples",
    },
}


def _config_from_spec(spec: dict[str, Any]) -> dict[str, Any]:
    """Resolve rule thresholds from a detection spec over DEFAULTS."""
    cfg = dict(DEFAULTS)
    for rule in spec.get("rules", []):
        if not isinstance(rule, dict):
            continue
        mapping = SPEC_THRESHOLD_KEYS.get(rule.get("id"))
        thresholds = rule.get("threshold")
        if not mapping or not isinstance(thresholds, dict):
            continue
        for spec_key, cfg_key in mapping.items():
            if spec_key in thresholds:
                cfg[cfg_key] = thresholds[spec_key]
    return cfg


def _load_runs(package: Package) -> list[dict[str, Any]]:
    runs_dir = package.root / "evidence" / "runs"
    if not runs_dir.is_dir():
        raise LabError(
            f"no evidence/runs for {package.cve}; run "
            f"`vulnforge validate {package.cve} --runs 3` first"
        )
    runs: list[dict[str, Any]] = []
    for path in sorted(runs_dir.glob("*.json")):
        try:
            runs.append(json.loads(path.read_text()))
        except json.JSONDecodeError as exc:
            raise LabError(f"invalid run evidence {path}: {exc}") from exc
    if not runs:
        raise LabError(f"no run evidence files in {runs_dir}")
    return runs


def _frames(result: dict[str, Any]) -> int:
    return int(result.get("n_frames") or result.get("n_chunks") or 0)


_ATTACK_RESULT_KEYS = ("one_byte_result", "chunked_result", "attack_result")


def _attack_result(observations: dict[str, Any]) -> dict[str, Any]:
    """The attack-phase observation, across probe naming conventions."""
    for key in _ATTACK_RESULT_KEYS:
        value = observations.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _payload(result: dict[str, Any]) -> int:
    return int(result.get("payload_bytes") or 0)


def _duration(result: dict[str, Any]) -> float:
    return float(result.get("elapsed_s") or 0.0)


def _connection(record: dict[str, Any]) -> ConnectionSample:
    observations = record.get("observations", {})
    attack = _attack_result(observations)
    metrics = record.get("metrics", {})
    return ConnectionSample(
        conn_id=f"run-{record.get('run', 0):02d}-{record.get('role')}",
        frames_or_chunks=_frames(attack),
        bytes_total=_payload(attack),
        duration_s=_duration(attack),
        attributable_memory_bytes=int(metrics.get("attack_memory_delta") or 0),
    )


def _control(record: dict[str, Any]) -> ConnectionSample:
    observations = record.get("observations", {})
    control = observations.get("control_result", {})
    metrics = record.get("metrics", {})
    return ConnectionSample(
        conn_id=f"run-{record.get('run', 0):02d}-{record.get('role')}-control",
        frames_or_chunks=_frames(control),
        bytes_total=_payload(control),
        duration_s=_duration(control),
        attributable_memory_bytes=int(metrics.get("control_memory_delta") or 0),
    )


def _benign(record: dict[str, Any]) -> list[ConnectionSample]:
    observations = record.get("observations", {})
    pool: list[ConnectionSample] = []
    for item in observations.get("benign_pool") or []:
        pool.append(
            ConnectionSample(
                conn_id=(
                    f"run-{record.get('run', 0):02d}-"
                    f"{record.get('role')}-{item.get('conn_id')}"
                ),
                frames_or_chunks=int(item.get("frames_or_chunks") or 1),
                bytes_total=int(item.get("bytes_total") or 0),
                duration_s=float(item.get("duration_s") or 0.0),
                attributable_memory_bytes=int(
                    item.get("attributable_memory_bytes") or 0
                ),
            )
        )
    return pool


def _history(record: dict[str, Any]) -> list[ProcessGrowthSample]:
    observations = record.get("observations", {})
    telemetry = (
        observations.get("telemetry", {}).get("attack")
        if isinstance(observations.get("telemetry"), dict)
        else None
    ) or []
    history: list[ProcessGrowthSample] = []
    for sample in telemetry:
        process_count = sample.get("process_count")
        top_memory = sample.get("top_process_memory")
        if not isinstance(process_count, int) or not isinstance(top_memory, int):
            return []
        history.append(
            ProcessGrowthSample(
                process_count=process_count,
                top_process_memory_bytes=top_memory,
                # The probe samples during the request; no request has
                # completed yet for the attack phase.
                completed_requests=0,
            )
        )
    return history


def _evaluate_role(
    records: list[dict[str, Any]],
    pool: list[ConnectionSample],
    cfg: dict[str, Any],
) -> dict[str, Any]:
    per_rule: dict[str, dict[str, Any]] = {}
    for record in records:
        sample = _connection(record)
        history = _history(record)
        for verdict in evaluate(sample, pool, history, cfg=cfg):
            entry = per_rule.setdefault(
                verdict.rule, {"triggered": False, "details": []}
            )
            entry["triggered"] = bool(entry["triggered"] or verdict.triggered)
            entry["details"].append(
                f"run {record.get('run')}: {verdict.detail}"
            )

    rules = [
        {
            "id": rule_id,
            "triggered": bool(entry["triggered"]),
            "detail": "; ".join(entry["details"]),
        }
        for rule_id, entry in sorted(per_rule.items())
    ]
    return {
        "version": records[0].get("version") if records else None,
        "result": "TRIGGERED" if any(rule["triggered"] for rule in rules) else "NOT_TRIGGERED",
        "rules": rules,
    }


def evaluate_package(package: Package) -> dict[str, Any]:
    records = _load_runs(package)
    pool: list[ConnectionSample] = []
    for record in records:
        pool.append(_control(record))
        pool.extend(_benign(record))

    spec_path = package.root / "detection" / "spec.json"
    spec: dict[str, Any] = {}
    if spec_path.is_file():
        spec = json.loads(spec_path.read_text())
    cfg = _config_from_spec(spec)

    targets = {
        role: _evaluate_role(
            [record for record in records if record.get("role") == role], pool, cfg
        )
        for role in ROLES
    }

    # A detection signal is useful when it fires on the vulnerable target and
    # not on the patched target. Frame-rate/body-duration rules may fire on
    # both because the same traffic reaches both targets; those are not
    # discriminating by themselves.
    vulnerable_rules = {
        rule["id"]: rule for rule in targets.get("vulnerable", {}).get("rules", [])
    }
    patched_rules = {
        rule["id"]: rule for rule in targets.get("patched", {}).get("rules", [])
    }
    discriminating = [
        rule_id
        for rule_id, rule in vulnerable_rules.items()
        if rule["triggered"] and not patched_rules.get(rule_id, {}).get("triggered", False)
    ]

    if targets["vulnerable"]["result"] == "TRIGGERED" and discriminating:
        result = "TRIGGERED"
        reason = (
            "vulnerable target triggered discriminating rule(s): "
            + ", ".join(discriminating)
        )
    elif targets["vulnerable"]["result"] == "NOT_TRIGGERED" and targets["patched"]["result"] == "NOT_TRIGGERED":
        result = "NOT_TRIGGERED"
        reason = "neither target triggered a behavioral rule"
    else:
        result = "INCONCLUSIVE"
        reason = (
            "rules fired on both targets or only on the patched target; "
            "no discriminating signal"
        )

    # Attach the declared expectations for auditability.
    expected: dict[str, dict[str, str]] = {
        rule["id"]: rule.get("expected", {})
        for rule in spec.get("rules", [])
        if isinstance(rule, dict)
    }
    for role, target in targets.items():
        for rule in target["rules"]:
            rule["expected"] = expected.get(rule["id"], {}).get(role, "unknown")

    return {
        "schema_version": "1.0",
        "cve": package.cve,
        "result": result,
        "reason": reason,
        "source": "evidence/runs + evidence/telemetry",
        "rules": targets["vulnerable"]["rules"],
        "targets": targets,
    }


def run_detection(package: Package) -> dict[str, Any]:
    result = evaluate_package(package)
    path = package.root / "detection" / "evidence.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + "\n")
    return result
