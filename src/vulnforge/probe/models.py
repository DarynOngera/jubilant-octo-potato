"""Probe-facing models."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..lab.models import ServicePlan


@dataclass(frozen=True)
class ProbeTarget:
    name: str
    base_url: str
    admin_url: str

    @property
    def host(self) -> str:
        return urlparse(self.base_url).hostname or ""

    @property
    def port(self) -> int:
        parsed = urlparse(self.base_url)
        if parsed.port is None:
            raise ValueError(f"target {self.name!r} has no explicit port: {self.base_url}")
        return parsed.port

    def admin_stats(self) -> dict[str, Any]:
        with urllib.request.urlopen(f"{self.admin_url.rstrip('/')}/stats", timeout=10) as response:
            return json.loads(response.read())

    def admin_gc(self, timeout: float = 10.0) -> bool:
        """Ask the lab to force a full-BEAM GC. Returns False on old images."""
        request = urllib.request.Request(
            f"{self.admin_url.rstrip('/')}/gc",
            data=b"",
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status == 200
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            return False

    @classmethod
    def from_service(cls, service: ServicePlan) -> "ProbeTarget":
        return cls(
            name=service.name,
            base_url=service.base_url,
            admin_url=service.admin_url,
        )


@dataclass
class ProbeResult:
    metrics: dict[str, float]
    observations: dict[str, Any] = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    sample_count: int = 0
    errors: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metrics": self.metrics,
            "observations": self.observations,
            "artifacts": self.artifacts,
            "duration_s": self.duration_s,
            "sample_count": self.sample_count,
            "errors": self.errors,
            "raw": self.raw,
        }

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "ProbeResult":
        """Adapt a legacy probe that returns a plain dict."""
        metrics = {
            str(key): float(value)
            for key, value in data.items()
            if isinstance(value, (int, float)) and not isinstance(value, bool)
        }
        return cls(
            metrics=metrics,
            observations={
                key: value
                for key, value in data.items()
                if isinstance(value, (str, bool, list, dict, type(None)))
            },
            raw=dict(data),
        )

    @classmethod
    def coerce(cls, value: "ProbeResult | dict[str, Any]") -> "ProbeResult":
        if isinstance(value, ProbeResult):
            return value
        if isinstance(value, dict):
            return cls.from_mapping(value)
        raise TypeError(f"probe returned unsupported result type: {type(value)!r}")
