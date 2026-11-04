"""Adapter loading from config."""
from __future__ import annotations

import importlib

from ..config import FactoryConfig
from ..errors import ConfigError
from .base import TargetAdapter


def load_adapter(cfg: FactoryConfig, target_name: str) -> TargetAdapter:
    target = cfg.target(target_name)
    if not target.adapter:
        raise ConfigError(
            f"target {target_name!r} has no adapter configured in config/vulnforge.yaml"
        )
    module_name, separator, class_name = target.adapter.partition(":")
    if not separator or not module_name or not class_name:
        raise ConfigError(
            f"invalid adapter reference {target.adapter!r}; expected "
            "'package.module:ClassName'"
        )
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise ConfigError(f"could not import adapter module {module_name!r}: {exc}") from exc
    try:
        adapter_cls = getattr(module, class_name)
    except AttributeError as exc:
        raise ConfigError(
            f"adapter module {module_name!r} has no class {class_name!r}"
        ) from exc

    app_dir = (cfg.root / target.app_dir).resolve() if target.app_dir else None
    return adapter_cls(repo_root=cfg.root, app_dir=app_dir)
