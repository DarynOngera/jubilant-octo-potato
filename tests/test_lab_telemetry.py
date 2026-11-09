"""Tests for host-side lab observability."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnforge.lab import docker  # noqa: E402
from vulnforge.lab.models import ServicePlan  # noqa: E402
from vulnforge.lab.telemetry import ContainerSampler  # noqa: E402


def _service(role: str) -> ServicePlan:
    return ServicePlan(
        role=role,
        name=role,
        version="1.0.0",
        image_tag=f"example/{role}:1.0.0",
        container_name=f"container-{role}",
        build_args={},
        labels={},
        base_url="http://127.0.0.1:4000",
        admin_url="http://127.0.0.1:4001",
        app_port=4000,
        admin_port=4001,
    )


class ContainerSamplerTests(unittest.TestCase):
    def test_docker_stats_normalizes_resource_units(self):
        output = (
            '{"Name":"container-vulnerable","CPUPerc":"12.50%",'
            '"MemUsage":"2.5MiB / 512MiB","MemPerc":"0.49%",'
            '"NetIO":"2kB / 3kB","BlockIO":"4MiB / 5MiB","PIDs":"7"}\n'
        )
        with mock.patch(
            "vulnforge.lab.docker.run",
            return_value=CompletedProcess(["docker"], 0, stdout=output, stderr=""),
        ):
            result = docker.container_stats(["container-vulnerable"])

        sample = result["container-vulnerable"]
        self.assertEqual(sample["memory_bytes"], 2_621_440)
        self.assertEqual(sample["memory_limit_bytes"], 536_870_912)
        self.assertEqual(sample["network_rx_bytes"], 2_000)
        self.assertEqual(sample["block_write_bytes"], 5_242_880)
        self.assertEqual(sample["cpu_ratio"], 0.125)
        self.assertEqual(sample["pids"], 7)

    def test_retains_role_specific_snapshots_and_shared_errors(self):
        services = {role: _service(role) for role in ("vulnerable", "patched")}

        def reader(names: list[str]):
            return {
                name: {"memory_bytes": 123, "cpu_ratio": 0.25, "raw": {}}
                for name in names
            }

        with ContainerSampler(services, interval_s=60, stats_reader=reader) as sampler:
            pass

        vulnerable = sampler.for_role("vulnerable")
        self.assertEqual(vulnerable["source"], "docker stats --no-stream")
        self.assertGreaterEqual(len(vulnerable["samples"]), 2)
        self.assertEqual(vulnerable["samples"][0]["container"]["memory_bytes"], 123)
        self.assertEqual(vulnerable["errors"], [])

    def test_records_reader_failures_without_raising(self):
        def reader(_names: list[str]):
            raise RuntimeError("Docker unavailable")

        with ContainerSampler(
            {"vulnerable": _service("vulnerable")}, interval_s=60, stats_reader=reader
        ) as sampler:
            pass

        observed = sampler.for_role("vulnerable")
        self.assertEqual(observed["samples"], [])
        self.assertGreaterEqual(len(observed["errors"]), 2)
        self.assertIn("Docker unavailable", observed["errors"][0]["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
