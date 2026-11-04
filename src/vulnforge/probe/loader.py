"""Load package-local probe modules."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Callable

from ..errors import PackageError
from ..models import ProbeManifest

ProbeCallable = Callable[..., Any]


def load_probe(package_root: Path, manifest: ProbeManifest) -> ProbeCallable:
    module_path = manifest.module_path(package_root)
    if not module_path.is_file():
        raise PackageError(f"probe module not found: {module_path}")
    module_name, _, function_name = manifest.entrypoint.partition(":")
    spec = importlib.util.spec_from_file_location(
        f"vulnforge_probe_{manifest.cve.replace('-', '_').lower()}",
        module_path,
    )
    if spec is None or spec.loader is None:
        raise PackageError(f"could not load probe module: {module_path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001 - surface import failures clearly
        raise PackageError(f"error importing probe {module_path}: {exc}") from exc
    try:
        function = getattr(module, function_name)
    except AttributeError as exc:
        raise PackageError(
            f"probe {module_path} has no function {function_name!r}"
        ) from exc
    if not callable(function):
        raise PackageError(
            f"probe entrypoint {manifest.entrypoint!r} is not callable"
        )
    return function
