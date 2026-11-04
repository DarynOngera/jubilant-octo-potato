"""
Shared helpers for every probe/PoC script: target resolution, lab-isolation
guardrails, admin-stats polling, and a tiny context-manager timer.

Every PoC MUST go through `require_lab_target()` rather than accepting an
arbitrary host/port on the command line -- this is what keeps the harness
from ever being pointed at a non-lab, non-loopback target by accident.
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RESEARCH_CFG = yaml.safe_load((REPO_ROOT / "config" / "research.yaml").read_text())
LAB_LIMITS = yaml.safe_load((REPO_ROOT / "config" / "lab-limits.yaml").read_text())


@dataclass
class Target:
    name: str
    base_url: str
    admin_url: str

    @property
    def host(self) -> str:
        return urlparse(self.base_url).hostname

    @property
    def port(self) -> int:
        return urlparse(self.base_url).port

    def admin_stats(self) -> dict:
        req = urllib.request.Request(f"{self.admin_url}/stats")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())


def _enforce_isolation(name: str, base_url: str) -> None:
    host = urlparse(base_url).hostname or ""
    allowed_iface = LAB_LIMITS["isolation"]["bind_interface"]
    if host != allowed_iface and host not in ("localhost",):
        raise SystemExit(
            f"REFUSING: target '{name}' host {host!r} is not {allowed_iface!r}. "
            f"This harness only ever attacks loopback-bound lab containers."
        )
    for bad in LAB_LIMITS["isolation"]["deny_if_hostname_in"]:
        if bad in name.lower() or bad in base_url.lower():
            raise SystemExit(f"REFUSING: target name/url contains banned substring {bad!r}.")


def require_lab_target(which: str, allow_single: bool = False,
                       pair: tuple[str, str] = ("vulnerable", "patched")) -> list[Target]:
    """
    which: 'vulnerable' | 'interim' | 'patched' | 'both'

    'both' expands to the probe's `pair`, which defaults to
    (vulnerable, patched). A probe for a CVE fixed later than the vulnerable
    checkpoint passes its own pair -- e.g. CVE-2026-116078 is fixed in 1.14.1,
    so its A/B run is (interim 1.14.0, patched 1.14.1), not (1.13.1, 1.14.1).
    Otherwise the comparison would conflate the 1.14.0 fixes with the 1.14.1
    fix it is trying to prove.

    Single-target runs are refused by default when lab-limits.yaml sets
    require_patched_control. The regression harness passes allow_single=True
    because it pairs each probe with its own vulnerability-appropriate target
    and a patched control itself.
    """
    cfg = RESEARCH_CFG["targets"]
    if pair[0] == pair[1]:
        raise SystemExit(f"REFUSING: A/B pair names are identical ({pair[0]!r}).")
    for n in pair:
        if n not in cfg:
            raise SystemExit(f"REFUSING: unknown target {n!r} in A/B pair {pair!r}.")
    require_control = LAB_LIMITS["experiment_bounds"].get("require_patched_control", True)
    if which != "both" and require_control and not allow_single:
        raise SystemExit(
            f"REFUSING: '{which}' is a single target, but lab-limits.yaml requires a "
            f"patched control in the same run. Use --target both, or run "
            f"tests/regression/compare_versions.py (which pairs targets explicitly)."
        )
    names = list(pair) if which == "both" else [which]
    targets = []
    for n in names:
        t = cfg[n]
        _enforce_isolation(n, t["base_url"])
        target = Target(name=n, base_url=t["base_url"], admin_url=t["admin_url"])
        try:
            target.admin_stats()
        except (urllib.error.URLError, ConnectionRefusedError, TimeoutError) as e:
            raise SystemExit(
                f"REFUSING/ABORTING: target '{n}' at {t['admin_url']} is not reachable ({e}). "
                f"Start the lab first: docker compose -f lab/compose.yaml up -d"
            )
        targets.append(target)
    return targets


class Timer:
    def __enter__(self):
        self._t0 = time.monotonic()
        return self

    def __exit__(self, *exc):
        self.elapsed = time.monotonic() - self._t0


class MemorySampler:
    """
    Poll the target's /admin/stats on a background thread while a probe is
    running and retain the peak total BEAM memory.

    Measuring *after* a request completes (the old behaviour) usually records
    freed memory and GC noise rather than the amplification under test. The
    sampler keeps the measurement window open for the whole send.
    """

    def __init__(self, target: Target, interval_s: float = 0.05):
        self.target = target
        self.interval_s = interval_s
        self.samples: list[int] = []
        self.errors = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _sample_once(self) -> None:
        try:
            stats = self.target.admin_stats()
            total = stats.get("erlang_memory", {}).get("total")
            if isinstance(total, int):
                self.samples.append(total)
        except Exception:
            self.errors += 1

    def _run(self) -> None:
        while not self._stop.wait(self.interval_s):
            self._sample_once()

    def __enter__(self) -> "MemorySampler":
        self._sample_once()
        self._thread = threading.Thread(
            target=self._run,
            name=f"stats-sampler-{self.target.name}",
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
        return max(self.samples) if self.samples else None


def validate_payload_budget(wire_bytes: int) -> None:
    """Refuse a run whose estimated wire cost exceeds the lab experiment bound."""
    ceiling = LAB_LIMITS["experiment_bounds"]["max_request_bytes_total"]
    if wire_bytes > ceiling:
        raise SystemExit(
            f"REFUSING: estimated wire bytes {wire_bytes} exceed the lab ceiling "
            f"{ceiling} (config/lab-limits.yaml). Reduce --n-chunks/--n-frames."
        )


def validate_duration_budget(seconds: float) -> None:
    """Refuse a deliberately paced run that exceeds the lab wall-clock bound."""
    ceiling = LAB_LIMITS["experiment_bounds"]["max_duration_seconds"]
    if seconds > ceiling:
        raise SystemExit(
            f"REFUSING: paced send would take {seconds:.1f}s, above the lab "
            f"ceiling {ceiling}s (config/lab-limits.yaml). Reduce --pace-ms or count."
        )
