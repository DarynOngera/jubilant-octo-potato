"""Lab lifecycle orchestration for a vulnerability package."""
from __future__ import annotations

import dataclasses
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from ..config import FactoryConfig
from ..errors import LabError
from ..models import LabTarget, Package
from ..paths import Paths
from ..targets.base import TargetAdapter
from . import docker, provenance
from .models import LabPlan, LabRuntime, ServicePlan
from .ports import allocate_ports


class LabOrchestrator:
    def __init__(self, cfg: FactoryConfig, paths: Paths, adapter: TargetAdapter):
        self.cfg = cfg
        self.paths = paths
        self.adapter = adapter

    def _runtime_dir(self, cve: str) -> Path:
        return self.paths.root / ".vulnforge" / "labs" / cve

    def plan(self, package: Package) -> LabPlan:
        manifest = package.manifest
        lab = package.lab
        if manifest is None or lab is None:
            raise LabError(f"package {package.cve} has no valid manifest/lab spec")
        if len(lab.targets) < 2:
            raise LabError(f"{package.cve} lab needs vulnerable and patched targets")

        ports = allocate_ports(len(lab.targets) * 2)
        git_commit = provenance.git_state(self.cfg.root).get("commit") or "unknown"
        services: dict[str, ServicePlan] = {}
        for index, target in enumerate(lab.targets):
            app_port = ports[index * 2]
            admin_port = ports[index * 2 + 1]
            image_tag = self.adapter.image_tag(package.cve, target.role, target.version)
            services[target.role] = ServicePlan(
                role=target.role,
                name=target.name,
                version=target.version,
                image_tag=image_tag,
                container_name=f"vulnforge-{package.cve.lower()}-{target.role}",
                build_args=self.adapter.build_args(
                    target.version, package.cve, target.role
                ),
                labels=self.adapter.labels(
                    package.cve, target.role, target.version, git_commit
                ),
                base_url=f"http://127.0.0.1:{app_port}",
                admin_url=f"http://127.0.0.1:{admin_port}",
                app_port=app_port,
                admin_port=admin_port,
            )

        runtime_dir = self._runtime_dir(package.cve)
        return LabPlan(
            cve=package.cve,
            target=manifest.adapter_name,
            lab_id=f"vulnforge-{package.cve.lower()}",
            network="labnet",
            compose_path=runtime_dir / "compose.yaml",
            runtime_path=runtime_dir / "runtime.json",
            services=services,
        )

    def _lab_target(self, package: Package, service: ServicePlan) -> LabTarget:
        assert package.lab is not None
        source = package.lab.target_by_role(service.role)
        if source is None:
            raise LabError(
                f"{package.cve} lab has no target for role {service.role!r}"
            )
        return LabTarget(
            role=source.role,
            name=source.name,
            version=source.version,
            base_url=service.base_url,
            admin_url=service.admin_url,
        )

    @staticmethod
    def _published_port(
        inspect: dict[str, Any] | None,
        container_port: int | None,
        fallback: int,
    ) -> int:
        if inspect is None or container_port is None:
            return fallback
        ports = (inspect.get("NetworkSettings") or {}).get("Ports") or {}
        bindings = ports.get(f"{container_port}/tcp") or []
        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            host_port = binding.get("HostPort")
            if host_port:
                return int(host_port)
        return fallback

    def _service_from_inspect(
        self,
        service: ServicePlan,
        inspect: dict[str, Any] | None,
    ) -> ServicePlan:
        app_container, admin_container = self.adapter.container_ports()
        app_port = self._published_port(inspect, app_container, service.app_port)
        if admin_container is None:
            admin_port = app_port
        else:
            admin_port = self._published_port(
                inspect, admin_container, service.admin_port
            )
        return dataclasses.replace(
            service,
            app_port=app_port,
            admin_port=admin_port,
            base_url=f"http://127.0.0.1:{app_port}",
            admin_url=f"http://127.0.0.1:{admin_port}",
        )

    def _published_services(self, plan: LabPlan) -> dict[str, ServicePlan]:
        services: dict[str, ServicePlan] = {}
        for role, service in plan.services.items():
            inspect = docker.container_inspect(service.container_name)
            services[role] = self._service_from_inspect(service, inspect)
        return services

    def render_compose(self, package: Package, plan: LabPlan) -> Path:
        assert package.lab is not None
        services: dict[str, Any] = {}
        for role, service in plan.services.items():
            target = package.lab.target_by_role(role)
            if target is None:
                raise LabError(f"{package.cve} lab has no target role {role!r}")
            rendered = self.adapter.service(target, service, package.lab.limits)
            rendered["networks"] = ["labnet"]
            services[role] = rendered

        document = {
            "name": plan.lab_id,
            "networks": {
                "labnet": {
                    "driver": "bridge",
                    # Docker on this host drops published port mappings for
                    # internal bridges; isolation is loopback bindings + caps.
                    "internal": False,
                }
            },
            "services": services,
        }
        plan.compose_path.parent.mkdir(parents=True, exist_ok=True)
        plan.compose_path.write_text(yaml.safe_dump(document, sort_keys=False))
        return plan.compose_path

    def build(self, package: Package, no_cache: bool = False) -> tuple[LabPlan, Path]:
        plan = self.plan(package)
        compose_path = self.render_compose(package, plan)
        build_args = ["build"]
        if no_cache:
            build_args.append("--no-cache")
        docker.compose(compose_path, *build_args)
        data = provenance.build_provenance(
            self.cfg, self.adapter, package, plan
        )
        provenance_path = provenance.write_provenance(package, data)
        return plan, provenance_path

    def start(self, package: Package) -> tuple[LabRuntime, Path]:
        plan = self.plan(package)
        compose_path = self.render_compose(package, plan)
        docker.compose(compose_path, "up", "-d", "--remove-orphans", "--build")
        plan = dataclasses.replace(plan, services=self._published_services(plan))
        self._wait_for_health(package, plan, timeout=90)

        runtime = LabRuntime(
            cve=package.cve,
            target=plan.target,
            lab_id=plan.lab_id,
            network=plan.network,
            compose_path=compose_path,
            runtime_path=plan.runtime_path,
            services=plan.services,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        plan.runtime_path.parent.mkdir(parents=True, exist_ok=True)
        plan.runtime_path.write_text(json.dumps(runtime.to_dict(), indent=2) + "\n")
        data = provenance.build_provenance(
            self.cfg, self.adapter, package, plan, runtime=runtime
        )
        provenance_path = provenance.write_provenance(package, data)
        return runtime, provenance_path

    def _wait_for_health(self, package: Package, plan: LabPlan, timeout: int) -> None:
        deadline = time.monotonic() + timeout
        failures: dict[str, str] = {}
        for role, service in plan.services.items():
            target = self._lab_target(package, service)
            while time.monotonic() < deadline:
                healthy, detail = self.adapter.health(target)
                if healthy:
                    break
                failures[role] = detail
                time.sleep(1)
            else:
                raise LabError(
                    f"{role} target {target.base_url} did not become healthy "
                    f"within {timeout}s: {failures.get(role)}"
                )

            stats = self.adapter.stats(target)
            if stats is None:
                raise LabError(
                    f"could not read /stats from {role} target {target.admin_url}"
                )
            actual = self.adapter.version_from_stats(stats)
            if actual != service.version:
                raise LabError(
                    f"{role} target reports version {actual!r}, expected "
                    f"{service.version!r}"
                )

    def stop(self, package: Package) -> bool:
        runtime_dir = self._runtime_dir(package.cve)
        compose_path = runtime_dir / "compose.yaml"
        runtime_path = runtime_dir / "runtime.json"
        if not compose_path.exists() and runtime_path.exists():
            try:
                data = json.loads(runtime_path.read_text())
                compose_path = Path(data["compose_path"])
            except (json.JSONDecodeError, KeyError):
                pass
        if compose_path.exists():
            docker.compose(compose_path, "down", "-v", "--remove-orphans")
        runtime_path.unlink(missing_ok=True)
        return True

    def status(self, package: Package) -> dict[str, Any]:
        runtime_dir = self._runtime_dir(package.cve)
        runtime_path = runtime_dir / "runtime.json"
        if not runtime_path.exists():
            return {
                "cve": package.cve,
                "running": False,
                "lab_id": f"vulnforge-{package.cve.lower()}",
                "reason": f"no runtime at {runtime_path}",
                "services": {},
            }
        try:
            data = json.loads(runtime_path.read_text())
            runtime = LabRuntime.from_dict(data)
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise LabError(f"invalid runtime file {runtime_path}: {exc}") from exc

        services: dict[str, Any] = {}
        for role, service in runtime.services.items():
            inspect = docker.container_inspect(service.container_name)
            service = self._service_from_inspect(service, inspect)
            running = bool(inspect and inspect.get("State", {}).get("Running"))
            target = self._lab_target(package, service)
            healthy, health_detail = self.adapter.health(target)
            stats = self.adapter.stats(target) if healthy else None
            services[role] = {
                "name": service.name,
                "version": service.version,
                "container_name": service.container_name,
                "base_url": service.base_url,
                "admin_url": service.admin_url,
                "app_port": service.app_port,
                "admin_port": service.admin_port,
                "image": service.image_tag,
                "image_id": (inspect or {}).get("Image"),
                "started_at": ((inspect or {}).get("State") or {}).get("StartedAt"),
                "running": running,
                "healthy": healthy,
                "health_detail": health_detail,
                "reported_version": (
                    self.adapter.version_from_stats(stats) if stats else None
                ),
            }
        return {
            "cve": package.cve,
            "running": any(svc["running"] for svc in services.values()),
            "lab_id": runtime.lab_id,
            "network": runtime.network,
            "created_at": runtime.created_at,
            "services": services,
        }
