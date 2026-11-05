"""VulnForge CLI entrypoint and compatibility surface."""
from __future__ import annotations

import sys
from pathlib import Path

from ..config import load_config
from ..errors import VulnForgeError
from ..paths import find_repo_root
from .parser import build_parser

__all__ = ["build_parser", "main"]


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        root = Path(args.root).expanduser().resolve() if args.root else find_repo_root()
        cfg = load_config(root)
        paths = cfg.paths()
        return int(args.func(args, cfg, paths))
    except VulnForgeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
