"""Thin Docker CLI backend.

Using the CLI instead of the Docker SDK keeps the dependency surface small and
makes every action visible/reproducible in the evidence log.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from ..errors import VulnForgeError


class DockerError(VulnForgeError):
    """A Docker command failed or returned unusable output."""


def run(
    args: list[str],
    *,
    check: bool = True,
    cwd: Path | None = None,
    timeout: int | None = 600,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise DockerError("docker is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise DockerError(f"command timed out after {timeout}s: {' '.join(args)}") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise DockerError(
            f"command failed ({result.returncode}): {' '.join(args)}\n{detail}"
        )
    return result


def compose(compose_path: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(
        ["docker", "compose", "-f", str(compose_path), *args],
        check=check,
    )


def image_inspect(tag: str) -> dict[str, Any]:
    result = run(["docker", "image", "inspect", tag])
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DockerError(f"could not parse `docker image inspect {tag}`") from exc
    if not rows:
        raise DockerError(f"image not found: {tag}")
    return rows[0]


def container_inspect(name: str) -> dict[str, Any] | None:
    result = run(["docker", "inspect", name], check=False)
    if result.returncode != 0:
        return None
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    return rows[0] if rows else None


_SIZE_UNITS = {
    "b": 1,
    "kb": 1_000,
    "kib": 1_024,
    "mb": 1_000_000,
    "mib": 1_048_576,
    "gb": 1_000_000_000,
    "gib": 1_073_741_824,
    "tb": 1_000_000_000_000,
    "tib": 1_099_511_627_776,
}
_SIZE_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)?\s*$")


def _bytes(value: str) -> int | None:
    match = _SIZE_RE.match(value)
    if match is None:
        return None
    unit = (match.group(2) or "b").lower()
    multiplier = _SIZE_UNITS.get(unit)
    if multiplier is None:
        return None
    return int(float(match.group(1)) * multiplier)


def _pair(value: str) -> tuple[int | None, int | None]:
    left, separator, right = value.partition("/")
    if not separator:
        return _bytes(left), None
    return _bytes(left), _bytes(right)


def _percent(value: str) -> float | None:
    try:
        return float(value.strip().removesuffix("%")) / 100
    except ValueError:
        return None


def container_stats(names: list[str]) -> dict[str, dict[str, Any]]:
    """Return one host-side Docker stats snapshot per named container.

    The Docker CLI exposes its portable table fields as strings. Keep those raw
    values for auditability and add normalized byte/ratio fields for evidence
    processing. A failed or partial snapshot raises ``DockerError`` rather than
    pretending missing measurements are zero.
    """
    if not names:
        return {}
    result = run(
        ["docker", "stats", "--no-stream", "--format", "{{json .}}", *names],
        timeout=15,
    )
    snapshots: dict[str, dict[str, Any]] = {}
    for line in result.stdout.splitlines():
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise DockerError(f"could not parse `docker stats` output: {line!r}") from exc
        name = str(raw.get("Name") or "")
        if not name:
            raise DockerError("`docker stats` returned a row without a container name")
        memory_current, memory_limit = _pair(str(raw.get("MemUsage") or ""))
        network_rx, network_tx = _pair(str(raw.get("NetIO") or ""))
        block_read, block_write = _pair(str(raw.get("BlockIO") or ""))
        try:
            pids = int(str(raw.get("PIDs") or ""))
        except ValueError:
            pids = None
        snapshots[name] = {
            "raw": raw,
            "cpu_ratio": _percent(str(raw.get("CPUPerc") or "")),
            "memory_bytes": memory_current,
            "memory_limit_bytes": memory_limit,
            "memory_ratio": _percent(str(raw.get("MemPerc") or "")),
            "network_rx_bytes": network_rx,
            "network_tx_bytes": network_tx,
            "block_read_bytes": block_read,
            "block_write_bytes": block_write,
            "pids": pids,
        }
    missing = sorted(set(names) - set(snapshots))
    if missing:
        raise DockerError(f"`docker stats` returned no rows for: {', '.join(missing)}")
    return snapshots
