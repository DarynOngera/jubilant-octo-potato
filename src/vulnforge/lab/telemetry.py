"""Host-side telemetry collection for a running lab."""
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from . import docker
from .models import ServicePlan

StatsReader = Callable[[list[str]], dict[str, dict[str, Any]]]


class ContainerSampler:
    """Poll Docker for resource use while a probe is running.

    The sampler runs outside target containers, so the target does not need a
    Docker socket or additional privileges. Sampling failures are retained in
    the result: absence of telemetry is evidence of an observation gap, never
    a zero-valued measurement.
    """

    def __init__(
        self,
        services: dict[str, ServicePlan],
        *,
        interval_s: float = 0.25,
        stats_reader: StatsReader = docker.container_stats,
    ):
        self.services = services
        self.interval_s = interval_s
        self.stats_reader = stats_reader
        self.samples: list[dict[str, Any]] = []
        self.errors: list[dict[str, str]] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._t0 = 0.0

    def _sample_once(self) -> None:
        observed_at = datetime.now(timezone.utc).isoformat()
        try:
            snapshots = self.stats_reader(
                [service.container_name for service in self.services.values()]
            )
            self.samples.append(
                {
                    "t": round(time.monotonic() - self._t0, 6),
                    "observed_at": observed_at,
                    "containers": {
                        role: snapshots[service.container_name]
                        for role, service in self.services.items()
                    },
                }
            )
        except Exception as exc:  # noqa: BLE001 - observation must not stop the probe
            self.errors.append({"observed_at": observed_at, "error": str(exc)})

    def _run(self) -> None:
        while not self._stop.wait(self.interval_s):
            self._sample_once()

    def __enter__(self) -> "ContainerSampler":
        self._t0 = time.monotonic()
        self._sample_once()
        self._thread = threading.Thread(
            target=self._run,
            name="vulnforge-container-telemetry",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(2, self.interval_s * 4))
        self._sample_once()

    def for_role(self, role: str) -> dict[str, Any]:
        """Return one role's host observations, retaining shared failures."""
        return {
            "source": "docker stats --no-stream",
            "interval_s": self.interval_s,
            "samples": [
                {
                    "t": sample["t"],
                    "observed_at": sample["observed_at"],
                    "container": sample["containers"].get(role),
                }
                for sample in self.samples
            ],
            "errors": list(self.errors),
        }
