"""Compatibility entrypoint for the VulnForge CLI.

The command implementations live in :mod:`vulnforge.commands`; this module
keeps ``vulnforge.cli:main`` and ``from vulnforge.cli import build_parser``
working for the installed console script and existing imports.
"""
from __future__ import annotations

from .commands import build_parser, main

__all__ = ["build_parser", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
