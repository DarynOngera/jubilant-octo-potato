"""Target-provided measurement contract for probes.

The probe runtime needs a small, target-neutral view of a live node: total
memory, process count, top process memory, and run-queue depth.  Targets that
expose BEAM-style ``/stats`` JSON can use :func:`read_beam_stats`; other
adapters can supply their own reader and endpoint paths through
:class:`MeasurementSpec`.

Keeping this out of ``MemorySampler`` is what lets a non-BEAM adapter provide
its own metrics without the core learning about nginx, Cowboy, or any other
runtime.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MeasurementSample:
    """One normalized sample from a target's stats endpoint."""

    total: int
    process_count: int | None = None
    top_process_memory: int = 0
    run_queue: int | None = None


StatsReader = Callable[[dict[str, Any]], MeasurementSample | None]


def read_beam_stats(stats: dict[str, Any]) -> MeasurementSample | None:
    """Read the BEAM-shaped payload used by the BEAM lab app."""
    total = stats.get("erlang_memory", {}).get("total")
    if not isinstance(total, int):
        return None
    top_processes = stats.get("top_processes") or []
    top_memory = max(
        (int(process.get("memory", 0)) for process in top_processes),
        default=0,
    )
    process_count = stats.get("process_count")
    run_queue = stats.get("run_queue")
    return MeasurementSample(
        total=total,
        process_count=process_count if isinstance(process_count, int) else None,
        top_process_memory=top_memory,
        run_queue=run_queue if isinstance(run_queue, int) else None,
    )


def read_toy_stats(stats: dict[str, Any]) -> MeasurementSample | None:
    """Read the native payload exposed by the toy target."""
    total = stats.get("memory_bytes")
    if not isinstance(total, int):
        return None
    process_count = stats.get("process_count")
    top_memory = stats.get("top_process_memory_bytes", 0)
    run_queue = stats.get("run_queue")
    return MeasurementSample(
        total=total,
        process_count=process_count if isinstance(process_count, int) else None,
        top_process_memory=int(top_memory) if isinstance(top_memory, int) else 0,
        run_queue=run_queue if isinstance(run_queue, int) else None,
    )


@dataclass(frozen=True)
class MeasurementSpec:
    """How a probe should read and trigger measurements for one target.

    ``reader`` normalizes an arbitrary JSON payload into a
    :class:`MeasurementSample`.  ``gc_path`` is ``None`` for targets that do
    not expose a forced-collection endpoint; ``ProbeTarget.admin_gc()`` then
    returns ``False`` without making a request.
    """

    stats_path: str = "/stats"
    health_path: str = "/healthz"
    gc_path: str | None = "/gc"
    reader: StatsReader = read_beam_stats
    # Single-listener targets (for example the toy adapter) serve stats from
    # the app listener rather than a separate admin listener.
    use_app_listener: bool = False


DEFAULT_MEASUREMENT = MeasurementSpec()
