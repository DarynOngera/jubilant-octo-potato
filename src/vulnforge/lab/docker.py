"""Thin Docker CLI backend.

Using the CLI instead of the Docker SDK keeps the dependency surface small and
makes every action visible/reproducible in the evidence log.
"""
from __future__ import annotations

import json
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
