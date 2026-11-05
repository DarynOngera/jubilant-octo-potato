"""Shared probe runtime: timing, memory sampling, budget and isolation guards."""
from __future__ import annotations

import threading
import time
import urllib.error
import urllib.request
from functools import lru_cache
from typing import Any

import yaml

from ..paths import find_repo_root
from .models import ProbeTarget


class ProbeBudgetError(ValueError):
    """A probe would exceed the configured lab experiment budget."""


@lru_cache(maxsize=1)
def load_limits() -> dict[str, Any]:
    root = find_repo_root()
    path = root / "config" / "lab-limits.yaml"
    if not path.exists():
        return {
            "isolation": {"bind_interface": "127.0.0.1", "deny_if_hostname_in": []},
            "experiment_bounds": {
                "max_duration_seconds": 120,
                "max_request_bytes_total": 268435456,
            },
        }
    return yaml.safe_load(path.read_text()) or {}


def enforce_loopback(target: ProbeTarget) -> None:
    limits = load_limits()
    isolation = limits.get("isolation", {})
    allowed = isolation.get("bind_interface", "127.0.0.1")
    if target.host not in (allowed, "localhost"):
        raise ProbeBudgetError(
            f"REFUSING: target {target.name!r} host {target.host!r} is not "
            f"{allowed!r}; probes only run against loopback lab targets"
        )
    haystack = f"{target.name} {target.base_url} {target.admin_url}".lower()
    for banned in isolation.get("deny_if_hostname_in", []):
        if banned.lower() in haystack:
            raise ProbeBudgetError(
                f"REFUSING: target {target.name!r} contains banned substring {banned!r}"
            )


def validate_payload_budget(wire_bytes: int) -> None:
    ceiling = int(load_limits()["experiment_bounds"]["max_request_bytes_total"])
    if wire_bytes > ceiling:
        raise ProbeBudgetError(
            f"REFUSING: estimated wire bytes {wire_bytes} exceed the lab ceiling "
            f"{ceiling} (config/lab-limits.yaml)"
        )


def validate_duration_budget(seconds: float) -> None:
    ceiling = int(load_limits()["experiment_bounds"]["max_duration_seconds"])
    if seconds > ceiling:
        raise ProbeBudgetError(
            f"REFUSING: paced send would take {seconds:.1f}s, above the lab "
            f"ceiling {ceiling}s (config/lab-limits.yaml)"
        )


class Timer:
    def __enter__(self):
        self._t0 = time.monotonic()
        return self

    def __exit__(self, *exc):
        self.elapsed = time.monotonic() - self._t0


class MemorySampler:
    """Poll /admin/stats during a probe and retain the peak + time series."""

    def __init__(self, target: ProbeTarget, interval_s: float = 0.02):
        self.target = target
        self.interval_s = interval_s
        self.samples: list[dict[str, float]] = []
        self.errors = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._t0 = 0.0

    def _sample_once(self) -> None:
        try:
            stats = self.target.admin_stats()
            sample = self.target.measurement.reader(stats)
            if sample is not None:
                self.samples.append(
                    {
                        "t": round(time.monotonic() - self._t0, 6),
                        "total": sample.total,
                        "process_count": sample.process_count,
                        "top_process_memory": sample.top_process_memory,
                        "run_queue": sample.run_queue,
                    }
                )
        except Exception:
            self.errors += 1

    def _run(self) -> None:
        while not self._stop.wait(self.interval_s):
            self._sample_once()

    def __enter__(self) -> "MemorySampler":
        self._t0 = time.monotonic()
        self._sample_once()
        self._thread = threading.Thread(
            target=self._run,
            name=f"vulnforge-stats-{self.target.name}",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)

    @property
    def peak(self) -> int | None:
        return max((int(sample["total"]) for sample in self.samples), default=None)


def _sample_total(target: ProbeTarget) -> int:
    stats = target.admin_stats()
    sample = target.measurement.reader(stats)
    return sample.total if sample is not None else 0


def capture_benign_pool(
    target: ProbeTarget,
    count: int = 8,
    path: str | None = None,
) -> list[dict[str, Any]]:
    """Capture a small normal-connection pool for the memory-outlier rule.

    The lab has only one attack connection; without a benign pool the outlier
    rule would have a pool size of one. These requests are cheap and are
    recorded in probe observations for offline detection.
    """
    pool: list[dict[str, Any]] = []
    health_path = path if path is not None else target.measurement.health_path
    url = f"{target.base_url.rstrip('/')}{health_path}"
    for index in range(count):
        before = _sample_total(target)
        started = time.monotonic()
        error = None
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                response.read()
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
            error = str(exc)
        elapsed = time.monotonic() - started
        after = _sample_total(target)
        pool.append(
            {
                "conn_id": f"benign-{index + 1}",
                "frames_or_chunks": 1,
                "bytes_total": 0,
                "duration_s": round(elapsed, 6),
                "attributable_memory_bytes": max(0, int(after) - int(before)),
                "error": error,
            }
        )
    return pool
